package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

public class StringUtils {
	// リクエストの編集
	public static String edit(IHttpRequestResponse[] messages) {
		StringBuilder sb = new StringBuilder();
		// 複数行選択時は逆順に処理する
		for (int i = messages.length - 1; i >= 0; i--) {
			if (messages[i].getRequest().length > 0) {
				sb.append(convertTsv(createUrlRows(messages[i])));
				sb.append(convertTsv(createParamRows(messages[i])));
				sb.append(convertTsv(createJsonRows(messages[i])));
			}
		}
		return sb.toString();
	}

	// TSV形式へ変換
	private static String convertTsv(List<List<String>> tsvList) {
		StringBuilder sb = new StringBuilder();
		for (List<String> cols : tsvList) {
			StringJoiner sj = new StringJoiner("\"\t\"", "\"", "\"");
			for (String col : cols) {
				sj.add(escapeString(col));
			}
			sb.append(sj.toString());
			sb.append(System.lineSeparator());
		}
		return sb.toString();
	}

	// 制御文字を空白、"を""に置換
	private static String escapeString(String value) {
		return value.replaceAll("[\\x00-\\x1F\\x7F]", "")
				.replace("\"", "\"\"");
	}

	// リクエスト情報からURL行を生成
	private static List<List<String>> createUrlRows(IHttpRequestResponse message) {
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		URL urlInfo = requestInfo.getUrl();
		String url = urlInfo.getProtocol() + "://" + urlInfo.getHost();
		int port = urlInfo.getPort();
		if (port != -1 && port != urlInfo.getDefaultPort()) {
			url += ":" + port;
		}
		url += urlInfo.getPath();
		return List.of(createUrlRow(requestInfo.getMethod(), url));
	}

	// TSV1行分の共通データを生成
	private static List<String> createRow(String method, String url, String type, String key, String value) {
		return List.of(
				url,
				type,
				key,
				editValue(value),
				method);
	}

	// URL情報用のTSV行を生成
	private static List<String> createUrlRow(String method, String url) {
		return createRow(
				method,
				url,
				"",
				"",
				"");
	}

	// パラメータ用のTSV行を生成
	private static List<String> createDataRow(String type, String key, String value) {
		return createRow(
				"",
				"",
				type,
				key,
				value);
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

	// URL・Cookie・Formパラメータを抽出
	private static List<List<String>> createParamRows(IHttpRequestResponse message) {
		List<List<String>> result = new ArrayList<>();
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		List<IParameter> parameters = requestInfo.getParameters();
		for (IParameter parameter : parameters) {
			String type;
			switch (parameter.getType()) {
				case IParameter.PARAM_URL:
					type = "URL";
					break;
				case IParameter.PARAM_COOKIE:
					type = "Cookie";
					break;
				case IParameter.PARAM_BODY:
				case IParameter.PARAM_MULTIPART_ATTR:
				case IParameter.PARAM_XML:
				case IParameter.PARAM_XML_ATTR:
					type = "Body";
					break;
				case IParameter.PARAM_JSON:
				default:
					continue;
			}
			result.add(createDataRow(type, parameter.getName(), decode(parameter.getValue())));
		}
		return result;
	}

	// ISO-8859-1として解釈された文字列をUTF-8へ補正
	private static String decode(String value) {
		if (value == null) {
			return "";
		}
		return new String(value.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
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

	// リクエスト情報からBodyを取得
	private static String getBody(IHttpRequestResponse message) {
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		byte[] bytes = Arrays.copyOfRange(
				message.getRequest(), requestInfo.getBodyOffset(), message.getRequest().length);
		return new String(bytes, StandardCharsets.UTF_8);
	}

	// JSON Bodyを解析して一覧化
	private static List<List<String>> createJsonRows(IHttpRequestResponse message) {
		List<List<String>> result = new ArrayList<>();
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		if (requestInfo.getContentType() != IRequestInfo.CONTENT_TYPE_JSON) {
			return Collections.emptyList();
		}
		String body = getBody(message);
		try {
			result.addAll(parseJson(JsonParser.parseString(body), "", "JSON1"));
		} catch (JsonSyntaxException e) {
			// NDJSON対応
			int i = 0;
			for (String row : body.split("\\R")) {
				if (row.isBlank()) {
					continue;
				}
				result.addAll(parseJson(JsonParser.parseString(row), "", "JSON" + (++i)));
			}
		}
		return result;
	}

	// JSONを再帰的に走査してキーと値の一覧へ展開
	private static List<List<String>> parseJson(JsonElement element, String parentKey, String type) {
		List<List<String>> result = new ArrayList<>();
		if (element.isJsonObject()) {
			JsonObject obj = element.getAsJsonObject();
			if (obj.isEmpty()) {
				result.add(createDataRow(type, parentKey, ""));
				return result;
			}
			for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
				String key = parentKey + "[" + entry.getKey() + "]";
				JsonElement value = entry.getValue();
				addJsonValue(result, value, key, type);
			}

		} else if (element.isJsonArray()) {
			JsonArray array = element.getAsJsonArray();
			if (array.isEmpty()) {
				result.add(createDataRow(type, parentKey, ""));
				return result;
			}
			int index = 0;
			for (JsonElement value : array) {
				String key = parentKey + "[" + index++ + "]";
				addJsonValue(result, value, key, type);
			}
		}
		return result;
	}

	// オブジェクト・配列は再帰展開し、それ以外は値として追加
	private static void addJsonValue(List<List<String>> result, JsonElement value, String key, String type) {
		if (value.isJsonObject() || value.isJsonArray()) {
			result.addAll(parseJson(value, key, type));
		} else if (value.isJsonNull()) {
			result.add(createDataRow(type, key, ""));
		} else {
			result.add(createDataRow(type, key, value.getAsString()));
		}
	}
}
