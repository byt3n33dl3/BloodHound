package cypher

const (
	CountFunction              = "count"
	DateFunction               = "date"
	TimeFunction               = "time"
	LocalTimeFunction          = "localtime"
	DateTimeFunction           = "datetime"
	LocalDateTimeFunction      = "localdatetime"
	DurationFunction           = "duration"
	IdentityFunction           = "id"
	ToLowerFunction            = "tolower"
	ToUpperFunction            = "toupper"
	NodeLabelsFunction         = "labels"
	EdgeTypeFunction           = "type"
	StringSplitToArrayFunction = "split"
	ToStringFunction           = "tostring"
	ToIntegerFunction          = "toint"
	ListSizeFunction           = "size"

	// ITTC - Instant Type; Temporal Component (https://neo4j.com/docs/cypher-manual/current/functions/temporal/)
	ITTCYear              = "year"
	ITTCMonth             = "month"
	ITTCDay               = "day"
	ITTCHour              = "hour"
	ITTCMinute            = "minute"
	ITTCSecond            = "second"
	ITTCMillisecond       = "millisecond"
	ITTCMicrosecond       = "microsecond"
	ITTCNanosecond        = "nanosecond"
	ITTCTimeZone          = "timezone"
	ITTCEpochSeconds      = "epochseconds"
	ITTCEpochMilliseconds = "epochmillis"
)