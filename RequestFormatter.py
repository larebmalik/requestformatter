# Burp Suite Extension - Request Formatter 
# Made by: Muhammad Lareb
# Version: 1.0

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
import json
from urlparse import urlparse, parse_qs

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request Formatter")
        callbacks.registerContextMenuFactory(self)
        
    def createMenuItems(self, context_menu_invocation):
        self.context = context_menu_invocation
        menu_list = []
        menu_item = JMenuItem("Request Formatter", actionPerformed=self.copy_formatted_request)
        menu_list.append(menu_item)
        return menu_list
        
    def copy_formatted_request(self, event):
        # Get the selected messages
        http_traffic = self.context.getSelectedMessages()
        
        if not http_traffic or len(http_traffic) == 0:
            return
            
        http_service = http_traffic[0].getHttpService()
        request_info = self._helpers.analyzeRequest(http_service, http_traffic[0].getRequest())
        
        # Get request components
        url = request_info.getUrl()
        if url is None:
            url = http_traffic[0].getUrl()
            if url is None:
                return
                
        method = request_info.getMethod()
        headers = request_info.getHeaders()
        body = http_traffic[0].getRequest()[request_info.getBodyOffset():].tostring()
        
        # Format the output
        formatted_output = self.format_request(url.toString(), method, headers, body)
        
        # Copy to clipboard
        self.copy_to_clipboard(formatted_output)
        
    def format_request(self, url, method, headers, body):
        try:
            parsed_url = urlparse(url)
            base_url = "{}://{}".format(parsed_url.scheme, parsed_url.netloc)
            endpoint = parsed_url.path
            
            # Get query parameters
            query_params = parse_qs(parsed_url.query)
            formatted_query = "&".join(["{}={}".format(k, v[0]) for k, v in query_params.items()])
            
            # Format the output
            output = []
            endpoint_parts = [p for p in endpoint.split('/') if p]
            if endpoint_parts:
                output.append(endpoint_parts[-1])
            else:
                output.append("request")
                
            output.append("    {}{}".format(base_url, endpoint))
            
            # Show GET parameters if they exist
            if formatted_query:
                output.append("        GET: {}".format(formatted_query))
            
            # Show POST body if it exists
            if body and body.strip():
                try:
                    json.loads(body)  # Validate JSON
                    output.append("        POST: {}".format(body.strip()))
                except ValueError:
                    output.append("        POST: {}".format(body.strip()))
            
            return "\n".join(output)
        except Exception as e:
            return "Error formatting request: {}".format(str(e))
        
    def copy_to_clipboard(self, text):
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)