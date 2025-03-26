from burp import IScanIssue
class CustomScanIssue(IScanIssue):
    def __init__(self, requestResponse, issueName, issueDetail, issueRemediation, severity, confidence):
        self._requestResponse = requestResponse
        self._issueName = issueName
        self._issueDetail = issueDetail
        self._severity = severity
        self._issueRemediation = issueRemediation
        self._confidence = confidence

    def getUrl(self):
        return self._requestResponse.getUrl()

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._issueDetail

    def getRemediationDetail(self):
        return self._issueRemediation

    def getHttpMessages(self):
        return [self._requestResponse]

    def getHttpService(self):
        return self._requestResponse.getHttpService()