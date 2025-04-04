from burp import IBurpExtender, IContextMenuFactory, IScanIssue
from javax import swing
import subprocess
import json


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("TLS Policy Scanner")

        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.issueAlert("TLS Scanner Extension Loaded!")

    def createMenuItems(self, invocation):
        menu = []
        menu_item = swing.JMenuItem("Scan TLS with sslyze")
        menu_item.addActionListener(lambda event: self.scan())
        menu.append(menu_item)
        return menu

    


    def scan(self):
        
        try:
            host = swing.JOptionPane.showInputDialog("Enter host (e.g., example.com):")
            output = subprocess.check_output(["python", "sslyzefin.py", host], universal_newlines=True)
            self._callbacks.issueAlert(output)
            result = json.loads(output)

            if result:

                if result["tls1.0"]:
                    self._callbacks.issueAlert("TLS 1.0 connected! Not recommended!")
                
                if result["tls1.1"]:
                    self._callbacks.issueAlert("TLS 1.1 connected! Not recommended!")
                
                if len(result["tls_1_2_bad"]) > 0:
                    for cipher in result["tls_1_2_bad"]:
                        message = cipher + " accepted. " + cipher + " not recommended."
                        self._callbacks.issueAlert(message)

                if len(result["tls_1_3_bad"]) > 0:
                    for cipher in result["tls_1_3_bad"]:
                        message = cipher + " accepted. " + cipher + " not recommended."
                        self._callbacks.issueAlert(message)



        except Exception as ex:
            self._callbacks.issueAlert(str(ex))
        

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