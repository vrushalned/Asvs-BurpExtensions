from burp import IBurpExtender
import math
from urllib.parse import parse_qs, urlparse

class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("ASVS-V13.1.3")

        self._secrets = self.scanUrls()

        #partial logic
        


    def scanUrls(self):
        try:
            with open("urls.txt", "r") as file:
                secrets = []
                lines = file.readlines()
                for line in lines:
                    parsed = urlparse(line)
                    params = parse_qs(parsed.query)
                    
                    for param in params:
                        entropy = self.calculateShannonEntropy(param)
                        ideal = self.idealEntropy(len(param))

                        if entropy > ideal:
                            secrets.append((line, param))
            file.close()

            return secrets

        except Exception as ex:
            print(ex)

    def calculateShannonEntropy(self,str):
        probability = [float(str.count(i))/len(str) for i in dict.fromkeys(list(str))]

        entropy = - sum([p * math.log(p)/math.log(2.0) for p in probability])
        return entropy
    
    def idealEntropy(self, length):
        probability = 1.0/length

        entropy = -1.0*length*probability*(math.log(probability)/math.log(2.0))
        return entropy
