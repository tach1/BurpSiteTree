package burp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

class StringUtilsTest {

    private int countJson(String json) throws Exception {
        Method method = StringUtils.class.getDeclaredMethod(
                "countJson",
                JsonElement.class);

        method.setAccessible(true);

        return (int) method.invoke(
                null,
                JsonParser.parseString(json));
    }

    @Test
    void rootPrimitiveString() throws Exception {
        assertEquals(1, countJson("\"test\""));
    }

    @Test
    void rootPrimitiveNumber() throws Exception {
        assertEquals(1, countJson("123"));
    }

    @Test
    void rootNull() throws Exception {
        assertEquals(1, countJson("null"));
    }

    @Test
    void emptyObject() throws Exception {
        assertEquals(1, countJson("{}"));
    }

    @Test
    void emptyArray() throws Exception {
        assertEquals(1, countJson("[]"));
    }

    @Test
    void arrayPrimitive() throws Exception {
        assertEquals(
                3,
                countJson("{\"items\":[1,2,3]}"));
    }

    @Test
    void complexObject() throws Exception {
        int count = countJson("{"
                + "\"obj\": {},"
                + "\"arr\": [],"
                + "\"nul\": null,"
                + "\"str\": \"test\","
                + "\"num\": 123,"
                + "\"bool\": true,"
                + "\"nested\": {"
                + "\"value\": \"abc\""
                + "},"
                + "\"items\": ["
                + "{"
                + "\"id\": [0,1]"
                + "},"
                + "{"
                + "\"name\": \"foo\","
                + "\"enabled\": false"
                + "}"
                + "]"
                + "}");

        assertEquals(11, count);
    }
}