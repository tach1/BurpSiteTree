package burp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

class StringUtilsTest {

    @SuppressWarnings("unchecked")
    private List<List<String>> parseJson(String json) throws Exception {
        Method method = StringUtils.class.getDeclaredMethod(
                "parseJson",
                JsonElement.class,
                String.class,
                String.class);

        method.setAccessible(true);

        return (List<List<String>>) method.invoke(
                null,
                JsonParser.parseString(json),
                "JSON1",
                "");
    }

    @Test
    void rootPrimitiveString() throws Exception {
        List<List<String>> rows = parseJson("\"test\"");

        assertEquals(1, rows.size());
        assertEquals("$", rows.get(0).get(2));
        assertEquals("test", rows.get(0).get(3));
    }

    @Test
    void rootPrimitiveNumber() throws Exception {
        List<List<String>> rows = parseJson("123");

        assertEquals(1, rows.size());
        assertEquals("$", rows.get(0).get(2));
        assertEquals("123", rows.get(0).get(3));
    }

    @Test
    void rootNull() throws Exception {
        List<List<String>> rows = parseJson("null");

        assertEquals(1, rows.size());
        assertEquals("$", rows.get(0).get(2));
        assertEquals("null", rows.get(0).get(3));
    }

    @Test
    void emptyObject() throws Exception {
        List<List<String>> rows = parseJson("{}");

        assertEquals(1, rows.size());
        assertEquals("$", rows.get(0).get(2));
        assertEquals("{}", rows.get(0).get(3));
    }

    @Test
    void emptyArray() throws Exception {
        List<List<String>> rows = parseJson("[]");

        assertEquals(1, rows.size());
        assertEquals("$", rows.get(0).get(2));
        assertEquals("[]", rows.get(0).get(3));
    }

    @Test
    void arrayPrimitive() throws Exception {
        List<List<String>> rows = parseJson("{\"items\":[1,2,3]}");

        assertEquals(3, rows.size());

        assertEquals("[items][0]", rows.get(0).get(2));
        assertEquals("1", rows.get(0).get(3));

        assertEquals("[items][1]", rows.get(1).get(2));
        assertEquals("2", rows.get(1).get(3));

        assertEquals("[items][2]", rows.get(2).get(2));
        assertEquals("3", rows.get(2).get(3));
    }

    @Test
    void complexObject() throws Exception {
        List<List<String>> rows = parseJson("{"
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

        assertEquals(11, rows.size());

        assertEquals("[obj]", rows.get(0).get(2));
        assertEquals("{}", rows.get(0).get(3));

        assertEquals("[arr]", rows.get(1).get(2));
        assertEquals("[]", rows.get(1).get(3));

        assertEquals("[nul]", rows.get(2).get(2));
        assertEquals("null", rows.get(2).get(3));

        assertEquals("[str]", rows.get(3).get(2));
        assertEquals("test", rows.get(3).get(3));

        assertEquals("[num]", rows.get(4).get(2));
        assertEquals("123", rows.get(4).get(3));

        assertEquals("[bool]", rows.get(5).get(2));
        assertEquals("true", rows.get(5).get(3));

        assertEquals("[nested][value]", rows.get(6).get(2));
        assertEquals("abc", rows.get(6).get(3));

        assertEquals("[items][0][id][0]", rows.get(7).get(2));
        assertEquals("0", rows.get(7).get(3));

        assertEquals("[items][0][id][1]", rows.get(8).get(2));
        assertEquals("1", rows.get(8).get(3));

        assertEquals("[items][1][name]", rows.get(9).get(2));
        assertEquals("foo", rows.get(9).get(3));

        assertEquals("[items][1][enabled]", rows.get(10).get(2));
        assertEquals("false", rows.get(10).get(3));
    }
}