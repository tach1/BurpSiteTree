package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
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
				sb.append(convertTsv(editUrl(messages[i])));
				sb.append(convertTsv(editParams(messages[i])));
				sb.append(convertTsv(editJson(messages[i])));
			}
		}
		return sb.toString();
	}

	// TSVを出力
	private static String convertTsv(List<List<String>> tsvList) {
		StringBuilder sb = new StringBuilder();
		if (tsvList != null) {
			for (List<String> cols : tsvList) {
				StringJoiner sj = new StringJoiner("\"\t\"", "\"", "\"");
				for (String col : cols) {
					sj.add(escapeString(col));
				}
				sb.append(sj.toString());
				sb.append(System.getProperty("line.separator"));
			}
		}
		return sb.toString();
	}

	// 制御文字を空白、"を""に置換する
	private static String escapeString(String value) {
		return value.replaceAll("[\\x00-\\x1F\\x7F]", "").replaceAll("\"", "\"\"");
	}

	// URLの編集
	private static List<List<String>> editUrl(IHttpRequestResponse messages) {
		List<List<String>> result = new ArrayList<>();
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messages);
		String url = String.format("%s://%s%s", requestInfo.getUrl().getProtocol(),
				requestInfo.getUrl().getHost(), requestInfo.getUrl().getPath());
		result.add(editData(requestInfo.getMethod(), url, "", "", ""));
		return result;
	}

	// 出力行の追加
	private static List<String> editData(String method, String url, String type, String name,
			String value) {
		return new ArrayList<String>(Arrays.asList(url, type, name, editValue(value), method));
	}

	// 値の編集
	private static String editValue(String value) {
		String result = "";
		if (value != null) {
			if (value.length() <= 4096) {
				result = value;
			} else {
				// 4096byteより大きいなら省略
				result = String.format("(%d bytes)", value.length());
			}
		}
		return result;
	}

	// Bodyの編集(JSON以外)
	private static List<List<String>> editParams(IHttpRequestResponse message) {
		List<List<String>> result = new ArrayList<>();
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message);
		List<IParameter> parameters = requestInfo.getParameters();
		for (IParameter parameter : parameters) {
			String type = "";
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
			result.add(editData("", "", type, parameter.getName(), decode(parameter.getValue())));
		}
		return result;
	}

	// 日本語文字化け対応
	private static String decode(String value) {
		String result = "";
		if (value != null) {
			byte[] bytes = value.getBytes(StandardCharsets.ISO_8859_1);
			result = new String(bytes, StandardCharsets.UTF_8);
		}
		return result;
	}

	// JSONの編集
	private static List<List<String>> editJson(IHttpRequestResponse message) {
		List<List<String>> result = new ArrayList<>();
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message);
		if (requestInfo.getContentType() != IRequestInfo.CONTENT_TYPE_JSON) {
			return null;
		}
		// Bodyを切り出してUTF-8に変換
		byte[] bytes = Arrays.copyOfRange(message.getRequest(), requestInfo.getBodyOffset(),
				message.getRequest().length);
		String body = new String(bytes, StandardCharsets.UTF_8);
		// 複数行JSON対応
		String[] rows = body.split("\n");
		int i = 0;
		for (String row : rows) {
			result.addAll(parseJson(row, "", String.format("JSON%d", ++i)));
		}
		return result;
	}

	// JSONのパース処理
	private static List<List<String>> parseJson(String json, String parentKey, String type) {
		List<List<String>> result = new ArrayList<>();
		JsonElement je = JsonParser.parseString(json);
		if (je.isJsonObject()) {
			Iterator<Map.Entry<String, JsonElement>> it =
					je.getAsJsonObject().entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<String, JsonElement> entry = it.next();
				String key = String.format("%s[%s]", parentKey, entry.getKey());
				if (entry.getValue().isJsonNull()) {
					result.add(editData("", "", type, key, ""));
				} else if (entry.getValue().isJsonObject()) {
					result.addAll(parseJson(entry.getValue().toString(), key, type));
				} else if (entry.getValue().isJsonArray()) {
					result.addAll(parseJson(entry.getValue().toString(), key, type));
				} else {
					result.add(editData("", "", type, key, entry.getValue().getAsString()));
				}
			}
		} else if (je.isJsonArray()) {
			int i = 0;
			for (JsonElement jea : je.getAsJsonArray()) {
				String key = String.format("%s[%d]", parentKey, i++);
				if (jea.isJsonNull()) {
					result.add(editData("", "", type, key, ""));
				} else if (jea.isJsonObject()) {
					result.addAll(parseJson(jea.getAsJsonObject().toString(), key, type));
				} else if (jea.isJsonArray()) {
					result.addAll(parseJson(jea.getAsJsonArray().toString(), key, type));
				} else {
					result.add(editData("", "", type, key, jea.getAsString()));
				}
			}
			if (i == 0) {
				// 子要素なし
				result.add(editData("", "", type, parentKey, ""));
			}
		}
		return result;
	}
}
