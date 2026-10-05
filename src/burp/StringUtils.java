package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.net.URL;
import java.nio.charset.StandardCharsets;
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
		// 複数選択時に画面上の表示順となるよう逆順で処理
		for (int i = messages.length - 1; i >= 0; i--) {
			IHttpRequestResponse message = messages[i];
			if (message.getRequest().length > 0) {
				sb.append(convertTsv(createUrlRows(message)));
			}
		}
		return sb.toString();
	}

	// TSV形式へ変換
	private static String convertTsv(List<List<String>> rows) {
		StringBuilder sb = new StringBuilder();
<<<<<<< HEAD
		for (List<String> row : rows) {
=======
		for (List<String> row : tsvList) {
>>>>>>> 3711c8b (refactor)
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
<<<<<<< HEAD
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		StringBuilder sb = new StringBuilder();
		URL requestUrl = requestInfo.getUrl();
		sb.append(requestUrl.getProtocol())
				.append("://")
				.append(requestUrl.getHost());
		int port = requestUrl.getPort();
		if (port != -1 && port != requestUrl.getDefaultPort()) {
			sb.append(":" + port);
		}
		sb.append(requestUrl.getPath());
		if (requestUrl.getQuery() != null) {
			sb.append("?" + requestUrl.getQuery());
		}
		return sb.toString();
=======
		URL requestUrl = BurpExtender.helpers.analyzeRequest(message).getUrl();
		String url = requestUrl.getProtocol() + "://" + requestUrl.getHost();
		if (requestUrl.getPort() != -1 && requestUrl.getPort() != requestUrl.getDefaultPort()) {
			url += ":" + requestUrl.getPort();
		}
		url += requestUrl.getPath();
		if (requestUrl.getQuery() != null) {
			url += "?" + requestUrl.getQuery();
		}
		return url;
>>>>>>> 3711c8b (refactor)
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
		int paramCount = getParamCount(message);
		if (paramCount == 0) {
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
		int paramCount = getParamCount(message);
		if (paramCount == 0) {
			sb.append("、パラメータ無し");
		} else {
			sb.append("、Params=").append(paramCount);
		}
		// リダイレクトかどうか
		short statusCode = getStatusCode(message);
		if (statusCode >= 300 && statusCode < 400) {
			sb.append("、リダイレクト");
		}
		// ステータスコード
		sb.append("、status:").append(statusCode);
		return sb.toString();
	}

	// リクエスト情報からMethodを取得
	private static String getMethod(IHttpRequestResponse message) {
		return BurpExtender.helpers.analyzeRequest(message).getMethod();
	}

	// リクエスト情報からパラメータ数を取得
	private static int getParamCount(IHttpRequestResponse message) {
		// URLとBodyとJSONのパラメータ数をカウント
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

	// URLとBodyのパラメータ数をカウント
	private static int getParamCountBody(IHttpRequestResponse message) {
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		List<IParameter> parameters = requestInfo.getParameters();
		int paramCount = 0;
		for (IParameter parameter : parameters) {
			switch (parameter.getType()) {
				case IParameter.PARAM_URL:
				case IParameter.PARAM_BODY:
				case IParameter.PARAM_MULTIPART_ATTR:
				case IParameter.PARAM_XML:
				case IParameter.PARAM_XML_ATTR:
					paramCount++;
					break;
			}
		}
		return paramCount;
	}

	// JSON Bodyを解析してパラメータ数をカウント
	private static int getParamCountJson(IHttpRequestResponse message) {
<<<<<<< HEAD
=======
		List<List<String>> jsonParams = new ArrayList<>();
>>>>>>> 3711c8b (refactor)
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);
		if (requestInfo.getContentType() != IRequestInfo.CONTENT_TYPE_JSON) {
			return 0;
		}
		String body = getBody(message);
		try {
<<<<<<< HEAD
			return countJson(JsonParser.parseString(body));
		} catch (JsonSyntaxException e) {
			// NDJSON対応
			int count = 0;
			for (String line : body.split("\\R")) {
				if (!line.isBlank()) {
					count += countJson(JsonParser.parseString(line));
				}
=======
			jsonParams.addAll(parseJson(JsonParser.parseString(body), ""));
		} catch (JsonSyntaxException e) {
			// NDJSON対応
			for (String line : body.split("\\R")) {
				if (line.isBlank()) {
					continue;
				}
				jsonParams.addAll(parseJson(JsonParser.parseString(line), ""));
>>>>>>> 3711c8b (refactor)
			}
			return count;
		}
	}

	// JSONを再帰的に走査してパラメータ数をカウント
	private static int countJson(JsonElement element) {
		if (element.isJsonObject()) {
			JsonObject obj = element.getAsJsonObject();
			if (obj.isEmpty()) {
				return 1;
			}
			int count = 0;
			for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
				count += countJson(entry.getValue());
			}
			return count;
		}
		if (element.isJsonArray()) {
			JsonArray array = element.getAsJsonArray();
			if (array.isEmpty()) {
				return 1;
			}
			int count = 0;
			for (JsonElement value : array) {
				count += countJson(value);
			}
			return count;
		}
		return 1;
	}
}
