package burp;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

public class StringUtils {
	// リクエストの編集
	public static String edit(List<HttpRequestResponse> messages) {
		StringBuilder sb = new StringBuilder();
		// 複数選択時に画面上の表示順となるよう逆順で処理
		for (int i = messages.size() - 1; i >= 0; i--) {
			HttpRequestResponse message = messages.get(i);
			sb.append(convertTsv(createUrlRows(message)));
			sb.append(convertTsv(createParameterRows(message)));
			sb.append(convertTsv(createJsonRows(message)));
		}
		return sb.toString();
	}

	// TSV形式へ変換
	private static String convertTsv(List<List<String>> rows) {
		StringBuilder sb = new StringBuilder();
		for (List<String> row : rows) {
			StringJoiner sj = new StringJoiner("\"\t\"", "\"", "\"");
			for (String col : row) {
				sj.add(escapeString(col));
			}
			sb.append(sj.toString());
			sb.append(System.lineSeparator());
		}
		return sb.toString();
	}

	// 制御文字を空白、"を""に置換
	private static String escapeString(String value) {
		return value.replaceAll("[\\x00-\\x1F\\x7F]", "").replace("\"", "\"\"");
	}

	// リクエスト情報からURL行を生成
	private static List<List<String>> createUrlRows(HttpRequestResponse message) {
		var request = message.request();
		StringBuilder sb = new StringBuilder();
		try {
			URL url = new URL(request.url());
			sb.append(url.getProtocol()).append("://").append(url.getHost());
			int port = url.getPort();
			if (port != -1 && port != url.getDefaultPort()) {
				sb.append(":").append(port);
			}
			sb.append(url.getPath());
			return List.of(createUrlRow(sb.toString(), request.method()));
		} catch (MalformedURLException e) {
			return Collections.emptyList();
		}
	}

	// TSV1行分の共通データを生成
	private static List<String> createRow(String url, String type, String key, String value,
			String method) {
		return List.of(url, type, key, editValue(value), method);
	}

	// URL情報用のTSV行を生成
	private static List<String> createUrlRow(String url, String method) {
		return createRow(url, "", "", "", method);
	}

	// パラメータ用のTSV行を生成
	private static List<String> createDataRow(String type, String key, String value) {
		return createRow("", type, key, value, "");
	}

	// TSV出力用に値を整形
	private static String editValue(String value) {
		if (value == null) {
			return "";
		}
		int byteLength = value.getBytes(StandardCharsets.UTF_8).length;
		if (isBinary(value)) {
			return String.format("(%d bytes)", byteLength);
		}
		if (byteLength > 4096) {
			return String.format("(%d bytes)", byteLength);
		}
		return value;
	}

	// URL・Cookie・Bodyパラメータを抽出
	private static List<List<String>> createParameterRows(HttpRequestResponse message) {
		List<List<String>> parameterRows = new ArrayList<>();
		var parameters = message.request().parameters();
		for (var parameter : parameters) {
			String type;
			switch (parameter.type()) {
			case URL:
				type = "URL";
				break;
			case COOKIE:
				type = "Cookie";
				break;
			case BODY:
			case MULTIPART_ATTRIBUTE:
			case XML:
			case XML_ATTRIBUTE:
				type = "Body";
				break;
			case JSON:
			default:
				continue;
			}
			parameterRows.add(createDataRow(type, parameter.name(), parameter.value()));
		}
		return parameterRows;
	}

	// バイナリデータか判定
	private static boolean isBinary(String value) {
		for (char c : value.toCharArray()) {
			if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') {
				return true;
			}
		}
		return false;
	}

	// JSON Bodyを解析して一覧化
	private static List<List<String>> createJsonRows(HttpRequestResponse message) {
		List<List<String>> jsonRows = new ArrayList<>();
		var request = message.request();
		if (request.contentType() != ContentType.JSON) {
			return Collections.emptyList();
		}
		var body = request.bodyToString();
		try {
			jsonRows.addAll(parseJson(JsonParser.parseString(body), "JSON1", ""));
		} catch (JsonSyntaxException e) {
			// NDJSON対応
			int i = 0;
			for (String line : body.split("\\R")) {
				if (line.isBlank()) {
					continue;
				}
				jsonRows.addAll(parseJson(JsonParser.parseString(line), "JSON" + (++i), ""));
			}
		}
		return jsonRows;
	}

	// JSONを再帰的に走査してキーと値の一覧へ展開
	private static List<List<String>> parseJson(JsonElement element, String type,
			String parentKey) {
		List<List<String>> entries = new ArrayList<>();
		if (element.isJsonObject()) {
			JsonObject obj = element.getAsJsonObject();
			if (obj.isEmpty()) {
				String key = parentKey.isEmpty() ? "$" : parentKey;
				return List.of(createDataRow(type, key, "{}"));
			}
			for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
				String key = parentKey + "[" + entry.getKey() + "]";
				addJsonValue(entries, type, key, entry.getValue());
			}
		} else if (element.isJsonArray()) {
			JsonArray array = element.getAsJsonArray();
			if (array.isEmpty()) {
				String key = parentKey.isEmpty() ? "$" : parentKey;
				return List.of(createDataRow(type, key, "[]"));
			}
			int index = 0;
			for (JsonElement value : array) {
				String key = parentKey + "[" + index++ + "]";
				addJsonValue(entries, type, key, value);
			}
		} else if (element.isJsonNull()) {
			String key = parentKey.isEmpty() ? "$" : parentKey;
			entries.add(createDataRow(type, key, "null"));
		} else {
			String key = parentKey.isEmpty() ? "$" : parentKey;
			entries.add(createDataRow(type, key, element.getAsString()));
		}
		return entries;
	}

	// オブジェクト・配列は再帰展開し、それ以外は値として追加
	private static void addJsonValue(List<List<String>> entries, String type, String key,
			JsonElement value) {
		if (value.isJsonObject() || value.isJsonArray()) {
			entries.addAll(parseJson(value, type, key));
		} else if (value.isJsonNull()) {
			entries.add(createDataRow(type, key, "null"));
		} else {
			entries.add(createDataRow(type, key, value.getAsString()));
		}
	}
}