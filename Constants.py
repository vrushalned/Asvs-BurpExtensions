#severity
LOW = "low"
HIGH = "high"

#confidence
UNCERTAIN = "uncertain"
CERTAIN = "certain"

#v13.1.1

INCONSISTENT_CONTENT_ENCODING = "The response encoding is inconsistent."
INCONSISTENT_CONTENT_ISSUE = "API Request Content-Type Inconsistency"
INCONSISTENT_CONTENT_ENCODING_TYPE = "The response Content-Type and encoding is inconsistent."
INCONSISTENT_CONTENT_TYPE = "The response Content-Type is inconsistent."
INCONSISTENT_CONTENT_REMEDIATION = "Content-type, encoding, and parsing throughout the application must be consistent."

#v13.1.5
UNSUPPORTED_CONTENT_MEDIA_ISSUE = "Unsupported content-type or media"
UNSUPPORTED_CONTENT_MEDIA_DETAILS = "Unsupported content-type or media accepted by the application"
UNSUPPORTED_CONTENT_MEDIA_REMEDIATION = "Ensure that the application is not accepting unsupported content-type and unsupported media type"

#statuscodes
UNACCEPTABLE = 406
UNSUPPORTED_MEDIA = 415