from burp import IBurpExtender, IContextMenuFactory, IScanIssue, ITab
from javax import swing
import subprocess
import json


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("TLS Policy Scanner")

        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.issueAlert("TLS Scanner Extension Loaded!")

        self._panel = swing.JPanel()
        self._panel.setLayout(swing.BoxLayout(self._panel, swing.BoxLayout.Y_AXIS))

        self._results_area = swing.JTextArea(15, 80)
        self._results_area.setEditable(False)
        scroll = swing.JScrollPane(self._results_area)
        self._panel.add(scroll)

        callbacks.addSuiteTab(self)


    def createMenuItems(self, invocation):
        menu = []
        menu_item = swing.JMenuItem("Scan TLS with sslyze")

        def doScan(event):
            try:
                request = invocation.getSelectedMessages()[0]
                http_service = request.getHttpService()
                host = http_service.getHost()
                self.scan(host)
            except Exception as e:
                self._callbacks.issueAlert("Error: " + str(e))


        menu_item.addActionListener(doScan)
        menu.append(menu_item)
        return menu
    
    def getTabCaption(self):
        return "TLS Security Summary"
    
    def getUiComponent(self):
        return self._panel
    

    


    def scan(self, host):
        
        try:
            #host = swing.JOptionPane.showInputDialog("Enter host (e.g., example.com):")
            output = subprocess.check_output(["python", "sslyzefin.py", host], universal_newlines=True)
           # self._callbacks.issueAlert(output)
            result = json.loads(output)

            summary = "TLS Security scan for " + host + ": \n\n"

            if result:

                if result["tls1.0"]:
                    summary +="TLS 1.0 connected! Not recommended!\n\n"
                else:
                    summary +="TLS 1.0 rejected.\n\n"
                
                if result["tls1.1"]:
                    summary +="TLS 1.1 connected! Not recommended!\n\n"
                else:
                    summary +="TLS 1.1 rejected.\n\n"
                
                if len(result["tls_1_2_bad"]) > 0:
                    summary += "TLS1.2 accepted unsafe ciphersuites:\n\n"
                    for cipher in result["tls_1_2_bad"]:
                        message = cipher + " accepted. " + cipher + " not recommended."
                        summary += message + "\n\n"
                else:
                    summary += "Unsafe TLS1.2 ciphersuites rejected!\n\n"
                    

                if len(result["tls_1_3_bad"]) > 0:
                    summary += "TLS1.3 accepted unsafe ciphersuites:\n\n"
                    for cipher in result["tls_1_3_bad"]:
                        message = cipher + " accepted. " + cipher + " not recommended."
                        summary += message + "\n\n"
                else:
                    summary += "Unsafe TLS1.3 ciphersuites rejected!\n\n"
            self._results_area.setText(summary)



        except Exception as ex:
            self._callbacks.issueAlert(str(ex))
            self._results_area.setText("Scan failed:\n" + str(ex))
        

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