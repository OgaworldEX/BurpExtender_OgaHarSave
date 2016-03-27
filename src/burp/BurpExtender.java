package burp;

import java.util.List;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import har.*;
import utils.HttpRequestResponse;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {

    private final static String EXTENDER_NAME = "OgaHarSave";
    private final static String EXTENDER_VERSION = "0.9";
    private final static String Har_VERSION = "1.2";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static PrintWriter burpStdout;
    private static PrintWriter burpStderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXTENDER_NAME);
        callbacks.registerContextMenuFactory(this);
        burpStdout = new PrintWriter(callbacks.getStdout(), true);
        burpStderr = new PrintWriter(callbacks.getStderr(), true);
        burpStdout.println(EXTENDER_NAME + " v" +EXTENDER_VERSION + " Load OK!");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> addMenuItemList = new ArrayList<>();

        JMenu menuOgaSave = new JMenu("OgaHarSave");
        menuOgaSave.addActionListener(null);
        addMenuItemList.add(menuOgaSave);

        JMenuItem menuItemSelected = new JMenuItem("Selected");
        menuItemSelected.addActionListener(e -> saveSelected(invocation));
        menuOgaSave.add(menuItemSelected);

        JMenuItem menuItemAll = new JMenuItem("All");
        menuItemAll.addActionListener(e -> saveAll(invocation));
        menuOgaSave.add(menuItemAll);

        return addMenuItemList;
    }

    private void saveSelected(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] httpReqRes = invocation.getSelectedMessages();
        if (httpReqRes.length < 0) {
            return;
        }
        Har outHar = getHarObject(httpReqRes);
        saveToFile(getJsonString(outHar));
    }

    private void saveAll(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] history = callbacks.getProxyHistory();
        Har outHar = getHarObject(history);
        saveToFile(getJsonString(outHar));
    }

    private Har getHarObject(IHttpRequestResponse[] iHttpRequestResponse) {

        List<IHttpRequestResponse> httpReqResList = Arrays.asList(iHttpRequestResponse);

        List<Pages> pages = new ArrayList<>();
        List<Entries> entries = new ArrayList<>();

        httpReqResList.forEach(requestResponse -> {
            IHttpService burpHttpService = requestResponse.getHttpService();
            IRequestInfo reqInfo = helpers.analyzeRequest(burpHttpService, requestResponse.getRequest());

            // String burpHighlight = requestResponse.getHighlight();
            byte[] burpHttpRequest = requestResponse.getRequest();
            byte[] burpHttpResponse = requestResponse.getResponse();

            Request request = new Request.Builder().method(reqInfo.getMethod()).url(reqInfo.getUrl().toString())
                    .httpVersion(HttpRequestResponse.getRequestHttpVersion(burpHttpRequest))
                    .cookies(HttpRequestResponse.createRequestCookieList(helpers, requestResponse))
                    .headers(HttpRequestResponse.createHeadersList(burpHttpRequest))
                    .queryString(HttpRequestResponse.createRequestQueryStringList(burpHttpRequest))
                    .postData(HttpRequestResponse.createPostData(helpers, requestResponse))
                    .headersSize(HttpRequestResponse.getHeaderSize(burpHttpRequest))
                    .bodySize(HttpRequestResponse.getBodySize(burpHttpRequest)).build();

            Response response = null;
            if (burpHttpResponse == null) {
                response = HttpRequestResponse.createEmptyResponse();
            } else {
                response = new Response.Builder().status(HttpRequestResponse.getResponseStatusCode(burpHttpResponse))
                        .statusText(HttpRequestResponse.getResponseStatusText(burpHttpResponse))
                        .httpVersion(HttpRequestResponse.getResponseVersion(burpHttpResponse))
                        .cookies(HttpRequestResponse.createResponseCookieList(helpers, requestResponse))
                        .headers(HttpRequestResponse.createHeadersList(burpHttpResponse))
                        .content(HttpRequestResponse.createContent(burpHttpResponse))
                        .redirectURL(HttpRequestResponse.getRedirectURL(burpHttpResponse))
                        .headersSize(HttpRequestResponse.getHeaderSize(burpHttpResponse))
                        .bodySize(HttpRequestResponse.getBodySize(burpHttpResponse)).build();
            }

            Cache cache = new Cache.Builder().build();

            Timings timings = new Timings.Builder().send(0).wait(0).build();

            Entries entrie = new Entries.Builder().startedDateTime("").time(1).request(request).response(response)
                    .cache(cache).timings(timings).comment(requestResponse.getComment()).build();

            entries.add(entrie);

            PageTimings pageTimings = new PageTimings.Builder().build();

            Pages tmpPages = new Pages.Builder().startedDateTime("").id("").title("").pageTimings(pageTimings).build();

            pages.add(tmpPages);

        });

        String[] version = callbacks.getBurpVersion();
        Browser browser = new Browser.Builder().name(version[0]).version(version[1]).build();

        Creator creator = new Creator.Builder().name(EXTENDER_NAME).version(EXTENDER_VERSION).build();

        Log log = new Log.Builder().version(Har_VERSION).creator(creator).browser(browser).pages(pages).entries(entries)
                .build();

        Har har = new Har.Builder(log).build();

        return har;

    }

    private String getJsonString(Object targetObject) {
        ObjectMapper mapper = new ObjectMapper();
        String json = "";
        try {
            json = mapper.writeValueAsString(targetObject);
        } catch (JsonProcessingException e) {
            burpStderr.println(e);
        }
        return json;
    }

    private void saveToFile(String saveStr) {
        String savefileName = getSaveFileName();
        try {
            File file = new File(getSaveFileName());
            PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(file)));
            printWriter.println(saveStr);
            printWriter.close();
            burpStdout.println("Save: " + savefileName);
        } catch (IOException e) {
            burpStderr.print("Save: " + savefileName);
            burpStderr.println(e);
        }
    }

    private String getSaveFileName() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd-HHmmssSS");
        StringBuilder sb = new StringBuilder();
        sb.append("./");
        sb.append(sdf.format(new Date()).toString());
        sb.append(".har");
        return new String(sb);
    }
}
