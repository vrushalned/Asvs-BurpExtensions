def automateRequests(self, file):
        requests = []
        try:
            with open(file, 'r') as src:
                lines = src.readlines()
                method = None
                contentType = None
                payload = None
                endpoint = None

                for line in lines:
                    line = line.strip()
                    
                    if line.startswith("POST") or line.startswith("GET"):
                        parts = line.split(" ")
                        method = parts[0]
                        endpoint = parts[1]

                    elif line.startswith("json") or line.startswith("xml") or line.startswith("text"):
                        content = line.split(" - ")
                        payload = content[1]
                        if content[0].lower() == "json":
                            contentType = "application/json"
                        elif content[0].lower() == "xml":
                            contentType = "application/xml"
                        elif content[0].lower() == "text":
                            contentType = "text/plain"
                        
                    elif line.startswith("-----"):
                        requests.append(
                            (method, endpoint, payload, contentType)
                        )

                        method = None
                        endpoint = None
                        payload = None
                        contentType = None
        except Exception as e:
            print("file not loaded properly")
        
        return requests