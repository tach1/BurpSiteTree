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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

public class StringUtils {
	// Excelの列に設定する式
	private static final String FORMULA = "=IF(ISERROR(SEARCH(\"重複\",INDIRECT(\"M\"&ROW()))), INDIRECT(\"Q\"&ROW()), "
			+ "INDIRECT(\"Q\"&ROW())&\"、No.\"&INDIRECT(\"P\"&ROW())&\" と同等の動きと思われる。\")";
	// Excelセルに格納可能な最大文字数
	private static final int EXCEL_CELL_MAX_LENGTH = 32767;

	// リクエストの編集
	public static String edit(List<HttpRequestResponse> messages) {
		StringBuilder sb = new StringBuilder();
		// 複数選択時に画面上の表示順となるよう逆順で処理
		for (int i = messages.size() - 1; i >= 0; i--) {
			HttpRequestResponse message = messages.get(i);
			sb.append(convertTsv(createRows(message)));
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

	// リクエスト情報から出力行を生成
	private static List<List<String>> createRows(HttpRequestResponse message) {
		return List.of(createRow(getUrl(message), isTarget(message), getRemark(message),
				getRequestBodyForExcel(message)));
	}

	// TSV1行分の共通データを生成
	private static List<String> createRow(String url, boolean isTarget, String remark,
			List<String> body) {
		List<String> row = new ArrayList<>();
		row.add(url);
		row.add(isTarget ? "対象" : "対象外");
		row.add("");
		row.add("");
		row.add("");
		row.add(remark);
		row.add(FORMULA);
		row.add("");
		row.addAll(body);
		return row;
	}

	// リクエスト情報からURLを生成
	private static String getUrl(HttpRequestResponse message) {
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
			String query = request.query();
			if (!query.isEmpty()) {
				sb.append("?").append(query);
			}
			return sb.toString();
		} catch (MalformedURLException e) {
			return sb.toString();
		}
	}

	// 診断対象かどうかを判定
	private static boolean isTarget(HttpRequestResponse message) {
		String method = message.request().method();
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
	private static String getRemark(HttpRequestResponse message) {
		StringBuilder sb = new StringBuilder();
		// メソッド
		sb.append(message.request().method());
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

	// リクエストBodyをExcelセル上限ごとに分割
	private static List<String> getRequestBodyForExcel(HttpRequestResponse message) {
		String text = message.request().bodyToString();
		if (text == null || text.isEmpty()) {
			return Collections.emptyList();
		}
		List<String> body = new ArrayList<>();
		for (int i = 0; i < text.length(); i += EXCEL_CELL_MAX_LENGTH) {
			body.add(text.substring(i, Math.min(i + EXCEL_CELL_MAX_LENGTH, text.length())));
		}
		return body;
	}

	// レスポンス情報からStatusCodeを取得
	private static short getStatusCode(HttpRequestResponse message) {
		if (!message.hasResponse()) {
			return 0;
		}
		return message.response().statusCode();
	}

	// リクエスト情報からパラメータ数を取得
	private static int getParamCount(HttpRequestResponse message) {
		// URLとBodyとJSONのパラメータ数をカウント
		return getParamCountBody(message) + getParamCountJson(message);
	}

	// URLとBodyのパラメータ数をカウント
	private static int getParamCountBody(HttpRequestResponse message) {
		var parameters = message.request().parameters();
		int paramCount = 0;
		for (var parameter : parameters) {
			switch (parameter.type()) {
			case URL:
			case BODY:
			case MULTIPART_ATTRIBUTE:
			case XML:
			case XML_ATTRIBUTE:
				paramCount++;
				break;
			default:
				continue;
			}
		}
		return paramCount;
	}

	// JSON Bodyを解析してパラメータ数をカウント
	private static int getParamCountJson(HttpRequestResponse message) {
		var request = message.request();
		if (request.contentType() != ContentType.JSON) {
			return 0;
		}
		String body = request.bodyToString();
		try {
			return countJson(JsonParser.parseString(body));
		} catch (JsonSyntaxException e) {
			// NDJSON対応
			int count = 0;
			for (String line : body.split("\\R")) {
				if (!line.isBlank()) {
					count += countJson(JsonParser.parseString(line));
				}
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