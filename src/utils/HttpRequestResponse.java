package utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;

import burp.*;
import har.*;

public class HttpRequestResponse {

    public static List<Headers> createHeadersList(byte[] httpMessage) {
        String message = new String(httpMessage);
        String[] httpHeaderBody = message.split("\r\n\r\n");
        String[] headerArray = httpHeaderBody[0].split("\r\n");
        ArrayList<String> burpHeadders = new ArrayList<>(Arrays.asList(headerArray));
        burpHeadders.remove(0);
        List<Headers> harHeadders = new ArrayList<>();
        burpHeadders.forEach(header -> harHeadders.add(createHarHeaders(header)));
        return harHeadders;
    }

    private static Headers createHarHeaders(String burpHeader) {
        String[] nameValue = burpHeader.split(": ");
        Headers header = new Headers.Builder().name(nameValue[0]).value(nameValue[1]).build();
        return header;
    }

    public static List<Cookies> createRequestCookieList(IExtensionHelpers helpers,
            IHttpRequestResponse requestResponse) {
        IHttpService burpHttpService = requestResponse.getHttpService();
        IRequestInfo reqInfo = helpers.analyzeRequest(burpHttpService, requestResponse.getRequest());
        List<String> burpHeadders = reqInfo.getHeaders();
        burpHeadders.remove(0);
        List<Cookies> retList = new ArrayList<>();
        for (String headder : burpHeadders) {
            if (headder.indexOf("Cookie: ") > -1) {
                String[] cookieFieldValue = headder.split(": ");
                String[] cookieValueSplit = cookieFieldValue[1].split("; ");

                for (String cookieKeyValue : cookieValueSplit) {
                    int equalPos = cookieKeyValue.indexOf("=");
                    Cookies addCookie = new Cookies.Builder().name(cookieKeyValue.substring(0, equalPos))
                            .value(cookieKeyValue.substring(equalPos + 1, cookieKeyValue.length())).build();
                    retList.add(addCookie);
                }
            }
        }

        return retList;
    }

    public static int getHeaderSize(byte[] httpMessage) {
        String messageString = new String(httpMessage);
        int headerPos = messageString.indexOf("\r\n\r\n");
        StringBuilder headder = new StringBuilder(messageString.substring(0, headerPos));
        headder.append("\r\n\r\n");

        return headder.toString().getBytes().length;
    }

    public static int getBodySize(byte[] httpMessage) {
        return getMessageBodyString(httpMessage).getBytes().length;
    }

    public static PostData createPostData(IExtensionHelpers helpers, IHttpRequestResponse requestResponse) {
        String requestString = new String(requestResponse.getRequest());
        String method = requestString.split("\r\n")[0].split(" ")[0];

        PostData retPostData = null;
        if ("POST".equals(method)) {
            String postBodytext = getMessageBodyString(requestResponse.getRequest());
            retPostData = new PostData.Builder().mimeType(getMimeType(requestResponse.getRequest()))
                    .params(createParamsList(helpers, requestResponse.getRequest())).text(postBodytext).build();
        } else {
            retPostData = new PostData.Builder().mimeType("").params(new ArrayList<>()).text("").build();
        }

        return retPostData;
    }

    private static List<Params> createParamsList(IExtensionHelpers helpers, byte[] postRequestBody) {
        ArrayList<Params> ret = new ArrayList<>();
        IRequestInfo iReqinfo = helpers.analyzeRequest(postRequestBody);
        List<IParameter> paramList = iReqinfo.getParameters();
        paramList.forEach(param -> {
            Params pm = new Params.Builder().name(param.getName()).value(param.getValue()).build();
            ret.add(pm);
        });
        return ret;
    }

    private static String getMessageBodyString(byte[] httpMessage) {
        String messageString = new String(httpMessage);
        int bodyPos = messageString.indexOf("\r\n\r\n");
        return messageString.substring(bodyPos + "\r\n\r\n".length(), messageString.length());
    }

    public static String getRequestHttpVersion(byte[] httpRequest) {
        String httpMessage = new String(httpRequest);
        String[] headder = httpMessage.split("\r\n");
        String[] requestLineArray = headder[0].split(" ");
        return requestLineArray[2];
    }

    public static List<QueryString> createRequestQueryStringList(byte[] httpRequest) {
        String[] response = new String(httpRequest).split("\r\n\r\n");
        String[] headder = response[0].split("\r\n");
        String[] requestLineArray = headder[0].split(" ");
        int queryStringStartPos = requestLineArray[1].indexOf("?");
        String queryString = requestLineArray[1].substring(queryStringStartPos + 1);
        String[] paramArray = queryString.split("&");

        List<QueryString> ret = new ArrayList<>();
        for (int i = 0; i < paramArray.length; i++) {
            int splitPos = paramArray[i].indexOf("=");

            QueryString qs = null;
            if (splitPos > -1) {
                qs = new QueryString.Builder().name(paramArray[i].substring(0, splitPos))
                        .value(paramArray[i].substring(splitPos + 1)).build();
            } else {
                qs = new QueryString.Builder().name("").value("").build();
            }
            ret.add(qs);
        }
        return ret;
    }

    public static int getResponseStatusCode(byte[] httpResponse) {
        String[] headder = new String(httpResponse).split("\r\n");
        String[] requestLineArray = headder[0].split(" ");
        return Integer.parseInt(requestLineArray[1]);
    }

    public static String getResponseStatusText(byte[] httpResponse) {
        String[] headder = new String(httpResponse).split("\r\n");
        int firstSpacePos = headder[0].indexOf(" ");
        int secondSpacePos = headder[0].indexOf(" ", firstSpacePos + 1);
        return headder[0].substring(secondSpacePos + 1);
    }

    public static String getResponseVersion(byte[] httpResponse) {
        String[] headder = new String(httpResponse).split("\r\n");
        String[] requestLineArray = headder[0].split(" ");
        return requestLineArray[0];
    }

    public static Content createContent(IExtensionHelpers helpers, byte[] httpResponse) {
        String[] response = new String(httpResponse).split("\r\n\r\n");

        // size
        int size = response[1].getBytes().length;

        // mimeType
        String mimeType = getMimeType(httpResponse);

        
        String base64String = "";
        if (response.length > 1) {
            IResponseInfo iResInfo =  helpers.analyzeResponse(httpResponse);
            int bodyPos = iResInfo.getBodyOffset();
            byte[] bodybyte = Arrays.copyOfRange(httpResponse,bodyPos,httpResponse.length);
            
            Encoder encoder = Base64.getMimeEncoder();
            encoder = Base64.getMimeEncoder();
            base64String = encoder.encodeToString(bodybyte);
        }

        Content retContent = new Content.Builder().size(size).compression(0).encoding("base64").mimeType(mimeType)
                .text(base64String).build();

        return retContent;
    }

    private static String getMimeType(byte[] message) {
        String[] response = new String(message).split("\r\n\r\n");
        List<String> headders = Arrays.asList(response[0].split("\r\n"));
        String contentType = "";
        for (String header : headders) {
            if (header.indexOf("Content-Type: ") > -1) {
                String[] locationHeadder = header.split(": ");
                contentType = locationHeadder[1];
                break;
            }
        }
        return contentType;
    }

    public static String getRedirectURL(byte[] httpResponse) {
        String responseMessage = new String(httpResponse);
        String[] headerResponse = responseMessage.split("\r\n\r\n");

        List<String> headders = Arrays.asList(headerResponse[0].split("0"));

        String ret = "";
        for (String header : headders) {
            if (header.indexOf("Location: ") > -1) {
                String[] locationHeadder = header.split(": ");
                ret = locationHeadder[1];
                break;
            }
        }
        return ret;
    }

    public static Response createEmptyResponse() {
        List<Cookies> cookies = new ArrayList<>();
        cookies.add(new Cookies.Builder().name("").value("").build());

        List<Headers> headers = new ArrayList<>();
        headers.add(new Headers.Builder().name("").value("").build());

        Content content = new Content.Builder().mimeType("text/plain").text("No Response").build();

        Response response = new Response.Builder().status(999).statusText("No Response").httpVersion("HTTP/1.0")
                .cookies(cookies).headers(headers).content(content).redirectURL("http://localhost").headersSize(0)
                .bodySize(0).build();

        return response;
    }

    public static List<Cookies> createResponseCookieList(IExtensionHelpers helpers,
            IHttpRequestResponse requestResponse) {
        List<Cookies> ret = new ArrayList<>();

        IResponseInfo respinfo = helpers.analyzeResponse(requestResponse.getResponse());
        List<ICookie> burpCookies = respinfo.getCookies();

        burpCookies.forEach(bCookie -> {

            String expires = null;
            if (bCookie.getExpiration() != null) {
                expires = bCookie.getExpiration().toString();
            }

            Cookies cookie = new Cookies.Builder().name(bCookie.getName()).value(bCookie.getValue()).expires(expires)
                    .domain(bCookie.getDomain()).path(bCookie.getPath()).build();
            ret.add(cookie);
        });

        return ret;
    }
}
