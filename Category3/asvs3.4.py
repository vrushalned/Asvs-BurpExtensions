from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpListener

class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("CookieAnalyzer")
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None
    
    def doPassiveScan(self, baseRequestResponse):
        self._callbacks.issueAlert("PassiveScan undergoing!")
        issues=[]
       
        issues = self.analyzeCookies(baseRequestResponse)

        

        return issues 
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            issues = []
            if messageIsRequest is True:
                self._callbacks.issueAlert("Request analysis undergoing!")
                request = self._helpers.analyzeRequest(messageInfo)
                requestHeaders = request.getHeaders()
                self._callbacks.issueAlert("Going into checkCookies!")
                issues = self.checkCookies(requestHeaders, messageIsRequest, messageInfo)

            else:
                self._callbacks.issueAlert("Response analysis undergoing!")
                #self._callbacks.issueAlert(str(messageIsRequest))
                response = self._helpers.analyzeResponse(messageInfo)
                responseHeaders = response.getHeaders()
                self._callbacks.issueAlert("Going into checkCookies!")
                issues = self.checkCookies(responseHeaders, messageIsRequest, messageInfo)
                

            self._callbacks.issueAlert(len(issues))

            for issue in issues:
                self._callbacks.issueAlert("Issue found: ")
                self._callbacks.issueAlert(issue.getIssueName())
                self._callbacks.addScanIssue(issue)
        except Exception as ex:
            self._callbacks.issueAlert(ex)


    
    def analyzeCookies(self, baseRequestResponse):
        issues = []
        
        headers = self._helpers.analyzeResponse(baseRequestResponse).getHeaders()

        issues = self.checkCookies(headers, False, baseRequestResponse)

        return issues
        

                    



           
            #issues.append(CustomScanIssue(baseRequestResponse,"Cookie",   
            #                                        cookieName, cookieValue, "Low", "Certain" ))
    

    def checkCookies(self,headers, isRequest, baseRequestResponse):
        try:
            issues = []
            self._callbacks.issueAlert("Inside checkCookies!")
            self._callbacks.issueAlert("Checking Cookies!")
            for header in headers:
                _hasHostPrefix = False
                _isSecure = False
                _isHttpOnly = False
                _hasSafePath = False
                _hasSameSiteProtection = False
                cookieKey = "cookie" if isRequest else "set-cookie"
                if header.strip().lower().startswith(cookieKey):
                    cookie = header.split(":")[1]
                    attributes = cookie.split(";")
                    for  attribute in attributes:
                        if attribute.lower().startswith("_host"):
                            _hasHostPrefix = True
                        if attribute.lower().startswith("secure"):
                            _isSecure = True
                        if attribute.lower().startswith("httponly"):
                            _isHttpOnly = True
                        if attribute.lower().startswith("path"):
                            path = attribute.split("=")[1]
                            if path != "/":
                                _hasSafePath = True
                        if attribute.lower().startswith("samesite"):
                            sameSite = attribute.split("=")[1]
                            if sameSite.lower() != "none":
                                _hasSameSiteProtection = True

                    if _hasHostPrefix is False:
                        issues.append(CustomScanIssue(baseRequestResponse,"Cookie Host prefix",   
                                                        "_Host- prefix is missing", "_Host- prefix must be added so cookies are only sent to the host that initially set the cookie.", "Low", "Certain" ))
                        
                    if _hasSafePath is False:
                        issues.append(CustomScanIssue(baseRequestResponse,"Cookie Path",   
                                                        "Path set to /", "Cookie path must be set to the mist precise path", "Low", "Certain" ))
                        
                    if _hasSameSiteProtection is False:
                        issues.append(CustomScanIssue(baseRequestResponse,"Cookie SameSite",   
                                                        "SameSite set to None", "Cookie SameSite must be set to value that limit exposure to cross-site scripting", "Low", "Certain" ))
                    if _isSecure is False:
                        issues.append(CustomScanIssue(baseRequestResponse,"Cookie Secure",   
                                                        "Secure attribute not set in cookie", "Cookie must contain the secure attribute enabled", "Low", "Certain" ))
                        
                    if _isHttpOnly is False:
                        issues.append(CustomScanIssue(baseRequestResponse,"Cookie HttpOnly",   
                                                        "HttpOnly attribute not set in cookie", "Cookie must contain the HttpOnly attribute enabled", "Low", "Certain" )) 

            return issues                    
        except Exception as ex:
            self._callbacks.issueAlert(ex)

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
