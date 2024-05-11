package com.jcmw.spring.backend.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Enumeration;

@RestController
@RequestMapping("/api")
public class BackendController {

    private static final Logger log = LoggerFactory.getLogger(BackendController.class);
    HttpHeaders predefinedHeaders;
    private String predefinedMessageBody = "Hello, World!";

    @GetMapping("/response")
    public ResponseEntity<String> getResponse() {
        log.info("The context path /api/response' was executed.");
        return ResponseEntity.status(200).headers(predefinedHeaders).body(predefinedMessageBody);
    }

    @GetMapping("/headers")
    public ResponseEntity<String> setHeaders(HttpServletRequest request) {
        log.info("The context path /api/headers' was executed.");
        predefinedHeaders = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            predefinedHeaders.put(headerName, Collections.singletonList(headerValue));
        }
        return ResponseEntity.accepted().body("Headers updated successfully, the updated headers are, " +
                predefinedHeaders.toString());
    }

    @PostMapping("/message-body")
    public ResponseEntity<String> setMessageBody(@RequestBody String messageBody) {
        log.info("The context path /api/message-body' executed.");
        predefinedMessageBody = messageBody;
        return ResponseEntity.accepted().body("Message body set successfully, the updated message body is " +
                messageBody);
    }
}
