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
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

public class StringUtils {
	// Excelの列に設定する式
	private static final String FORMULA = "=IF(ISERROR(SEARCH(\"重複\",INDIRECT(\"M\"&ROW()))), INDIRECT(\"Q\"&ROW()), "
			+ "INDIRECT(\"Q\"&ROW())&\"、No.\"&INDIRECT(\"P\"&ROW())&\" と同等の動きと思われる。\")";

	// リクエストの編集
	public static String edit(IHttpRequestResponse[] messages) {
		StringBuilder sb = new StringBuilder();
		// 複数行選択時は逆順に処理する
		for (int i = messages.length - 1; i >= 0; i--) {
			if (messages[i].getRequest().length > 0) {
				sb.append(convertTsv(createUrlRows(messages[i])));
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
		return List.of(createRow(
				getUrl(message),
				isTarget(message),
				getRemark(message),
				getBody(message)));
	}

	// TSV1行分の共通データを生成
	private static List<String> createRow(String url, boolean isTarget, String remark, String body) {
		return List.of(
				url,
				isTarget ? "対象" : "対象外",
				"", "", "",
				remark,
				FORMULA,
				"",
				body);
	}

	// リクエスト情報からURLを取得
	private static String getUrl(IHttpRequestResponse message) {
		URL url = BurpExtender.helpers.analyzeRequest(message).getUrl();
		String result = url.getProtocol() + "://" + url.getHost();
		if (url.getPort() != -1 && url.getPort() != url.getDefaultPort()) {
			result += ":" + url.getPort();
		}
		result += url.getPath();
		if (url.getQuery() != null) {
			result += "?" + url.getQuery();
		}
		return result;
	}

	// 診断対象かどうかを判定
	private static boolean isTarget(IHttpRequestResponse message) {
		String method = getMethod(message);
		if (!List.of("GET", "POST", "PUT", "DELETE", "PATCH").contains(method)) {
			return false;
		}
		short statusCode = getStatusCode(message);
		if (statusCode < 200 || statusCode >= 400) {
			return false;
		}
		int count = getParamCount(message);
		if (count == 0) {
			return false;
		}
		return true;
	}

	// リクエスト情報から備考を生成
	private static String getRemark(IHttpRequestResponse message) {
		StringBuilder sb = new StringBuilder();
		// メソッド
		sb.append(getMethod(message));
		// パラメータ数
		int count = getParamCount(message);
		if (count == 0) {
			sb.append("、パラメータ無し");
		} else {
			sb.append(String.format("、Params=%d", count));
		}
		// リダイレクトかどうか
		short statusCode = getStatusCode(message);
		if (statusCode >= 300 && statusCode < 400) {
			sb.append("、リダイレクト");
		}
		// ステータスコード
		sb.append(String.format("、status:%d", statusCode));
		return sb.toString();
	}

	// リクエスト情報からMethodを取得
	private static String getMethod(IHttpRequestResponse message) {
		return BurpExtender.helpers.analyzeRequest(message).getMethod();
	}

	// リクエスト情報からパラメータ数を取得
	private static int getParamCount(IHttpRequestResponse message) {
		// URLとBodyとJSONのパラメタ数をカウント
		return getParamCountBody(message) + getParamCountJson(message);
	}

	// レスポンス情報からStatusCodeを取得
	private static short getStatusCode(IHttpRequestResponse message) {
		if (message.getResponse() == null) {
			return 0;
		}
		return BurpExtender.helpers.analyzeResponse(message.getResponse()).getStatusCode();
	}

	// リクエスト情報からBodyを取得
	private static String getBody(IHttpRequestResponse message) {
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		byte[] bytes = Arrays.copyOfRange(
				message.getRequest(), requestInfo.getBodyOffset(), message.getRequest().length);
		return new String(bytes, StandardCharsets.UTF_8);
	}

	// URLとBodyのパラメタ数をカウント
	private static int getParamCountBody(IHttpRequestResponse message) {
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		List<IParameter> parameters = requestInfo.getParameters();
		int count = 0;
		for (IParameter parameter : parameters) {
			switch (parameter.getType()) {
				case IParameter.PARAM_URL:
				case IParameter.PARAM_BODY:
				case IParameter.PARAM_MULTIPART_ATTR:
				case IParameter.PARAM_XML:
				case IParameter.PARAM_XML_ATTR:
					count++;
					break;
			}
		}
		return count;
	}

	// JSON Bodyを解析して一覧化してパラメータ数をカウント
	private static int getParamCountJson(IHttpRequestResponse message) {
		List<List<String>> result = new ArrayList<>();
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		if (requestInfo.getContentType() != IRequestInfo.CONTENT_TYPE_JSON) {
			return 0;
		}
		String body = getBody(message);
		try {
			result.addAll(parseJson(JsonParser.parseString(body), ""));
		} catch (JsonSyntaxException e) {
			// NDJSON対応
			for (String row : body.split("\\R")) {
				if (row.isBlank()) {
					continue;
				}
				result.addAll(parseJson(JsonParser.parseString(row), ""));
			}
		}
		return result.size();
	}

	// JSONを再帰的に走査してキーと値の一覧へ展開
	private static List<List<String>> parseJson(JsonElement element, String parentKey) {
		List<List<String>> result = new ArrayList<>();
		if (element.isJsonObject()) {
			JsonObject obj = element.getAsJsonObject();
			if (obj.isEmpty()) {
				result.add(List.of(parentKey, ""));
				return result;
			}
			for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
				String key = parentKey + "[" + entry.getKey() + "]";
				JsonElement value = entry.getValue();
				addJsonValue(result, value, key);
			}

		} else if (element.isJsonArray()) {
			JsonArray array = element.getAsJsonArray();
			if (array.isEmpty()) {
				result.add(List.of(parentKey, ""));
				return result;
			}
			int index = 0;
			for (JsonElement value : array) {
				String key = parentKey + "[" + index++ + "]";
				addJsonValue(result, value, key);
			}
		}
		return result;
	}

	// オブジェクト・配列は再帰展開し、それ以外は値として追加
	private static void addJsonValue(List<List<String>> result, JsonElement value, String key) {
		if (value.isJsonObject() || value.isJsonArray()) {
			result.addAll(parseJson(value, key));
		} else if (value.isJsonNull()) {
			result.add(List.of(key, ""));
		} else {
			result.add(List.of(key, value.getAsString()));
		}
	}
}
