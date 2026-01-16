package com.demo.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

/**
 * Worker Service - Java with vulnerable dependencies
 */
public class Worker {
    private static final Logger logger = LogManager.getLogger(Worker.class);
    private static final String DB_URL = "jdbc:postgresql://postgres:5432/vulndb";
    private static final String DB_USER = "vulnuser";
    private static final String DB_PASS = "vulnpass";

    public static void main(String[] args) {
        logger.info("Worker service starting...");

        try {
            // Test database connection
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            Statement stmt = conn.createStatement();
            stmt.execute("SELECT 1");
            logger.info("Database connection successful");
            conn.close();

            // Simulated worker loop
            while (true) {
                processJob();
                Thread.sleep(10000);
            }
        } catch (Exception e) {
            logger.error("Worker error: " + e.getMessage());
        }
    }

    private static void processJob() {
        logger.info("Processing job...");
        String data = StringUtils.upperCase("worker processing");
        logger.info("Job processed: " + data);
    }
}
