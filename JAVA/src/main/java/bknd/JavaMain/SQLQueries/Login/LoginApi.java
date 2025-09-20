package bknd.JavaMain.SQLQueries.Login;

import bknd.JavaMain.Verify.VerifyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import bknd.JavaMain.PlaywithJSON.controllerJSON;

import javax.crypto.spec.PSource;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.*;

@CrossOrigin(origins="http://localhost:5173")
@RestController
@RequestMapping()
public class LoginApi {

    @Autowired
    public JdbcTemplate jdbcTemplate;

    public List<Map<String,Object>> complexList = new ArrayList<>();

    @Autowired
    public controllerJSON check;

    @Autowired
    public VerifyService verifyotp;




    @GetMapping("/test-db")
    public String testConnection() {
        try {
            String result = jdbcTemplate.queryForObject("SELECT version()", String.class);
            return "Database connected: " + result;
        } catch (Exception e) {
            return "Database connection failed: " + e.getMessage();
        }
    }




    @GetMapping(value="/users", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> getComplexList() {
        List<Map<String, Object>> resultQuery = jdbcTemplate.queryForList(
                "SELECT * FROM users"
        );
        return resultQuery;
    }




    @PostMapping(value="/user/append", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> appendToComplexList(@RequestBody Map<String, Object> newItem) {
        try {
            // Extract values from request body
            String name = (String) newItem.get("name");
            String email = (String) newItem.get("email");
            String mobile = (String) newItem.get("mobile");
            String password = (String) newItem.get("password");

            // Validate required fields
            if (name == null || email == null || password == null) {
                return ResponseEntity.ok()
                        .body(List.of(Map.of("value", "Name, email, mobile and password are required")));
            }
            List<Map<String, Object>> resultQuery = jdbcTemplate.queryForList(
                    "SELECT * FROM users where email = ?", email
            );
            if(resultQuery.toArray().length > 0){
                return ResponseEntity.ok()
                        .body(List.of(Map.of(
                                "value", "Email already exists"
                        )));
            }
            // Generate random account ID
            String characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            Random random = new Random();
            StringBuilder idBuilder = new StringBuilder(6);
            for (int i = 0; i < 6; i++) {
                idBuilder.append(characters.charAt(random.nextInt(characters.length())));
            }
            String accID = idBuilder.toString();

            // Execute INSERT query using JdbcTemplate
            int affectedRows = jdbcTemplate.update(
                    "INSERT INTO users (account_id, name, email, mobile, password) VALUES (?, ?, ?, ?, ?)",
                    accID, name, email, mobile, password
            );

            if (affectedRows > 0) {
                return ResponseEntity.ok()
                        .body(List.of(Map.of(
                                "value", "Data inserted successfully",
                                "account_id", accID,
                                "affected_rows", affectedRows
                        )));
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(List.of(Map.of("value", "Failed to insert data")));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(List.of(Map.of("value", "Server error: " + e.getMessage())));
        }
    }





    @PostMapping(value="/user/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>>  verifyemail(@org.jetbrains.annotations.NotNull @RequestBody Map<String, Object> newItem) {
        try{
            String id = (String) newItem.get("email");
            List<Map<String, Object>> result = jdbcTemplate.queryForList(
                    "select * from users where email= ? ", id
            );
            if(result.toArray().length > 0){
                String otp = verifyotp.VerifyUserThroughOTP(id);
                return ResponseEntity.ok().body(List.of(Map.of(
                        "value", "exist",
                        "otp", otp
                )));
            } else {
                return ResponseEntity.ok().body(List.of(Map.of(
                        "value", "inValid email"
                )));
            }

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(List.of(Map.of(
                    "value", "not a valid request"
            )));
        }
    }





    @PostMapping(value="/user/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> loginMethod(@RequestBody Map<String, Object> newItem){
        try {
            String id = (String) newItem.get("email");
            String password = (String) newItem.get("password");
            String otp = (String) newItem.get("otp");

            boolean hasValidIdPassword = id != null && password != null &&
                    !id.isBlank() && !password.isBlank();

            boolean hasValidIdOtp = id != null && otp != null &&
                    !id.isBlank() && !otp.isBlank();

            if (!hasValidIdPassword && !hasValidIdOtp) {
                return ResponseEntity.badRequest().body(List.of(Map.of(
                        "value", "Either password or OTP must be provided with email"
                )));
            }

            if (hasValidIdPassword) {
                List<Map<String, Object>> result = jdbcTemplate.queryForList(
                        "select * from users where email= ? and password = ?", id, password
                );
                if (result.toArray().length > 0) {
                    String accVal = (String) result.get(0).get("account_id");
                    return ResponseEntity.ok().body(List.of(Map.of(
                            "value", "exist",
                            "account_id", accVal
                    )));
                } else {
                    return ResponseEntity.ok().body(List.of(Map.of(
                            "value", "not valid"
                    )));
                }
            } else {
                List<Map<String, Object>> result = jdbcTemplate.queryForList(
                        "select * from users where email= ? ", id
                );
                if (result.toArray().length > 0) {
                    String accVal = (String) result.get(0).get("account_id");
                    return ResponseEntity.ok().body(List.of(Map.of(
                            "value", "exist",
                            "account_id", accVal
                    )));
                } else {
                    return ResponseEntity.ok().body(List.of(Map.of(
                            "value", "not valid"
                    )));
                }
            }

        } catch(Exception e){
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(List.of(Map.of(
                    "value", "not a valid user"
            )));
        }
    }





    @PostMapping(value="/user/info", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> loginInfo(@RequestBody Map<String, Object> newItem){
        try{
            String id = (String) newItem.get("id");

            List<Map<String, Object>> result = jdbcTemplate.queryForList(
                    "select * from users where account_id= ? ", id
            );
            return ResponseEntity.ok().body(result);
        } catch(Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(List.of(Map.of(
                    "value", "not a valid user"
            )));
        }
    }




    @PostMapping(value="/user/remove", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> popFromComplexList(@RequestBody Map<String, Object> newItem) {
        try{
            String id = (String) newItem.get("id");
            if(id == null){
                return ResponseEntity.badRequest()
                        .body(List.of(Map.of("value", "Account Id cannot be null")));
            }
            int affectRow = jdbcTemplate.update("delete from users where account_id= ?", id);
            if(affectRow > 0){
                return ResponseEntity.ok()
                        .body(List.of(Map.of(
                                "value", "successfully deleted the record",
                                "affected_rows", affectRow
                        )));
            }  else {
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(List.of(Map.of(
                                "value", "something went wrong"
                        )));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(List.of(Map.of(
                            "value", "successfully deleted the record"
                    )));
        }
    }


}
