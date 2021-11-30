from burp import IBurpExtender, IProxyListener, IHttpListener, IHttpService
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IProxyListener, IHttpListener, IHttpService):
    def registerExtenderCallbacks( self, callbacks):
        extName = "Modify Response"
        # keep a reference to our callbacks object and add helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName(extName)

        # obtain our output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)

        # print extension name
        self._stdout.println(extName)

        return

    def processProxyMessage(self, messageIsRequest, message):

        hostTarget = "portswigger-labs.net"
        toReplace = "<head>"
        replacement = "<head><script>alert(1)</script>"

        # check if it's a response
        if (messageIsRequest == False):
            # retrieve IHttpRequestResponse object
            httpRequestResponse = message.getMessageInfo()
            # determine the host
            host = httpRequestResponse.getHttpService().getHost()
            # only replace on matching host
            if (host == hostTarget):
                # fetch response and convert to string
                respB = httpRequestResponse.getResponse()
                respS = self._helpers.bytesToString(respB)
                # match and replace, convert back to byte[]
                insertedString = respS.replace(toReplace,replacement,1)
                newB = self._helpers.stringToBytes(insertedString)
                # set response to the new one
                httpRequestResponse.setResponse(newB)
        return
