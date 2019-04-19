# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/aws_config"
require "logstash/timestamp"
require "time"
require "stud/interval"
require "aws-sdk"
require "logstash/inputs/cloudwatch_logs/patch"
require "fileutils"
require "set"

Aws.eager_autoload!

# Stream events from CloudWatch Logs streams.
#
# Specify an individual log group, and this plugin will scan
# all log streams in that group, and pull in any new log events.
#
# Optionally, you may set the `log_group_prefix` parameter to true
# which will scan for all log groups matching the specified prefix
# and ingest all logs available in all of the matching groups.
#
class LogStash::Inputs::CloudWatch_Logs < LogStash::Inputs::Base
  include LogStash::PluginMixins::AwsConfig::V2

  config_name "cloudwatch_logs"

  default :codec, "plain"

  # Log group(s) to use as an input. If `log_group_prefix` is set
  # to `true`, then each member of the array is treated as a prefix
  config :log_group, :validate => :string, :list => true

  # Where to write the since database (keeps track of the date
  # the last handled log stream was updated). The default will write
  # sincedb files to some path matching "$HOME/.sincedb*"
  # Should be a path with filename not just a directory.
  config :sincedb_path, :validate => :string, :default => nil

  # Interval to wait between to check the file list again after a run is finished.
  # Value is in seconds.
  config :interval, :validate => :number, :default => 60

  # Decide if log_group is a prefix or an absolute name
  config :log_group_prefix, :validate => :boolean, :default => false

  # When a new log group is encountered at initial plugin start (not already in
  # sincedb), allow configuration to specify where to begin ingestion on this group.
  # Valid options are: `beginning`, `end`, or an integer, representing number of
  # seconds before now to read back from.
  config :start_position, :default => 'beginning'

  # filters to search for and match terms, phrases, or values in your log events
  config :filter_pattern, :validate => :string, :default => nil

  # Buffer in seconds from the start time to search for delayed events in Cloudwatch
  config :filter_buffer_time, validate: :number, default: 5 * 1000

  # def register
  public
  def register
    require "digest/md5"
    @logger.debug("Registering cloudwatch_logs input", :log_group => @log_group)
    settings = defined?(LogStash::SETTINGS) ? LogStash::SETTINGS : nil
    @sincedb = {}

    check_start_position_validity

    Aws::ConfigService::Client.new(aws_options_hash)
    @cloudwatch = Aws::CloudWatchLogs::Client.new(aws_options_hash)

    if @sincedb_path.nil?
      if settings
        datapath = File.join(settings.get_value("path.data"), "plugins", "inputs", "cloudwatch_logs")
        # Ensure that the filepath exists before writing, since it's deeply nested.
        FileUtils::mkdir_p datapath
        @sincedb_path = File.join(datapath, ".sincedb_" + Digest::MD5.hexdigest(@log_group.join(",")))
      end
    end

    # This section is going to be deprecated eventually, as path.data will be
    # the default, not an environment variable (SINCEDB_DIR or HOME)
    if @sincedb_path.nil? # If it is _still_ nil...
      if ENV["SINCEDB_DIR"].nil? && ENV["HOME"].nil?
        @logger.error("No SINCEDB_DIR or HOME environment variable set, I don't know where " \
                      "to keep track of the files I'm watching. Either set " \
                      "HOME or SINCEDB_DIR in your environment, or set sincedb_path in " \
                      "in your Logstash config for the file input with " \
                      "path '#{@path.inspect}'")
        raise
      end

      #pick SINCEDB_DIR if available, otherwise use HOME
      sincedb_dir = ENV["SINCEDB_DIR"] || ENV["HOME"]

      @sincedb_path = File.join(sincedb_dir, ".sincedb_" + Digest::MD5.hexdigest(@log_group.join(",")))

      @logger.info("No sincedb_path set, generating one based on the log_group setting",
                   :sincedb_path => @sincedb_path, :log_group => @log_group)
    end

  end #def register

  public
  def check_start_position_validity
    raise LogStash::ConfigurationError, "No start_position specified!" unless @start_position

    return if @start_position =~ /^(beginning|end)$/
    return if @start_position.is_a? Integer

    raise LogStash::ConfigurationError, "start_position '#{@start_position}' is invalid! Must be `beginning`, `end`, or an integer."
  end # def check_start_position_validity

  # def run
  public
  def run(queue)
    @queue = queue
    @priority = []
    _sincedb_open
    determine_start_position(find_log_groups, @sincedb)

    while !stop?
      begin
        groups = find_log_groups

        groups.each do |group|
          @logger.debug("calling process_group on #{group}")
          process_group(group)
        end # groups.each
      rescue Aws::CloudWatchLogs::Errors::ThrottlingException
        @logger.debug("reached rate limit")
      end

      Stud.stoppable_sleep(@interval) { stop? }
    end
  end # def run

  public
  def find_log_groups
    if @log_group_prefix
      @logger.debug("log_group prefix is enabled, searching for log groups")
      groups = []
      next_token = nil
      @log_group.each do |group|
        loop do
          log_groups = @cloudwatch.describe_log_groups(log_group_name_prefix: group, next_token: next_token)
          groups += log_groups.log_groups.map {|n| n.log_group_name}
          next_token = log_groups.next_token
          @logger.debug("found #{log_groups.log_groups.length} log groups matching prefix #{group}")
          break if next_token.nil?
        end
      end
    else
      @logger.debug("log_group_prefix not enabled")
      groups = @log_group
    end
    # Move the most recent groups to the end
    groups.sort{|a,b| priority_of(a) <=> priority_of(b) }
  end # def find_log_groups

  private
  def priority_of(group)
    @priority.index(group) || -1
  end

  public
  def determine_start_position(groups, sincedb)
    groups.each do |group|
      if !sincedb.member?(group)
        case @start_position
          when 'beginning'
            sincedb[group] = { start_time: 0 }

          when 'end'
            sincedb[group] = { start_time: DateTime.now.strftime('%s').to_i * 1000 }

          else
            sincedb[group] = { start_time: (DateTime.now.strftime('%s').to_i * 1000) - (@start_position * 1000) }
        end # case @start_position
      end
    end
  end # def determine_start_position

  private
  def process_group(group)
    if !@sincedb.member?(group)
      @sincedb[group] = { start_time: DateTime.now.strftime('%s').to_i * 1000, prev_ids: Set[], new_ids: Set[] }
    end
    @sincedb[group][:end_time] = DateTime.now.strftime('%s').to_i * 1000
    @sincedb[group][:new_ids] ||= Set[]
    @sincedb[group][:prev_ids] ||= Set[]
    token = nil

    loop do
      params = {
        log_group_name: group,
        start_time: @sincedb[group][:start_time] - @filter_buffer_time,
        end_time: @sincedb[group][:end_time],
        interleaved: true,
        next_token: token,
        filter_pattern: @filter_pattern,
      }

      resp = @cloudwatch.filter_log_events(params)
      @logger.debug("CWL response contains #{resp.events.length} from #{parse_time(params[:start_time])} to #{parse_time(params[:end_time])}")
      resp.events.each do |event|
        processed = process_log(event, group)
      end

      token = resp.next_token
      unless token
        @sincedb[group] = {
          start_time: @sincedb[group][:end_time],
          prev_ids: @sincedb[group][:new_ids],
        }
        break
      end
    rescue Aws::CloudWatchLogs::Errors::ThrottlingException
      @logger.info("reached rate limit - #{params[:start_time]} - #{params[:end_time]}")
      # Wait 500ms and retry
      Stud.stoppable_sleep(0.5) { stop? }
    end

    _sincedb_write

    @priority.delete(group)
    @priority << group
  end #def process_group

  # def process_log
  private
  def process_log(log, group)
    start_time = @sincedb[group][:start_time]
    prev_ids = @sincedb[group][:prev_ids]
    end_time = @sincedb[group][:end_time]

    # Skips event ingested after start time to prevent duplicate event
    return if log.ingestion_time < start_time || prev_ids.include?(log.event_id)

    @sincedb[group][:new_ids] << log.event_id if log.ingestion_time > end_time
    if Time.at(log.ingestion_time/1000) - Time.at(log.timestamp/1000) > 30
      @logger.info("Event log delayed for more than 30 sec -- Delay #{Time.at(log.ingestion_time/1000) - Time.at(log.timestamp/1000)}")
    end

    @codec.decode(log.message.to_str) do |event|
      event.set("@timestamp", parse_time(log.timestamp))
      event.set("[cloudwatch_logs][ingestion_time]", parse_time(log.ingestion_time))
      event.set("[cloudwatch_logs][log_group]", group)
      event.set("[cloudwatch_logs][log_stream]", log.log_stream_name)
      event.set("[cloudwatch_logs][event_id]", log.event_id)
      decorate(event)

      @queue << event
    end
  end # def process_log

  # def parse_time
  private
  def parse_time(data)
    LogStash::Timestamp.at(data.to_i / 1000, (data.to_i % 1000) * 1000)
  end # def parse_time

  private
  def _sincedb_open
    begin
      File.open(@sincedb_path) do |db|
        @logger.debug? && @logger.debug("_sincedb_open: reading from #{@sincedb_path}")
        db.each do |line|
          group, start_time, prev_ids = line.split(" ", 3)
          @sincedb[group] = { start_time: start_time.to_i, prev_ids: prev_ids.to_s.split(" ").to_set }
        end
      end
    rescue
      #No existing sincedb to load
      @logger.debug? && @logger.debug("_sincedb_open: error: #{@sincedb_path}: #{$!}")
    end
  end # def _sincedb_open

  private
  def _sincedb_write
    begin
      IO.write(@sincedb_path, serialize_sincedb)
    rescue Errno::EACCES
      # probably no file handles free
      # maybe it will work next time
      @logger.debug? && @logger.debug("_sincedb_write: error: #{@sincedb_path}: #{$!}")
    end
  end # def _sincedb_write


  private
  def serialize_sincedb
    @sincedb.map do |group, values|
      [group, values[:start_time], values[:prev_ids].to_a].flatten.join(" ")
    end.join("\n") + "\n"
  end
end # class LogStash::Inputs::CloudWatch_Logs
