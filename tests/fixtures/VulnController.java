package com.example;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

public class VulnController {
    private Connection conn;

    public void handleRequest(HttpServletRequest request) throws Exception {
        String username = request.getParameter("user");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }
}
