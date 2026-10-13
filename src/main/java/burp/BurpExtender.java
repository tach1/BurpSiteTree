package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.settings.SettingsPanel;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

public class BurpExtender implements BurpExtension {
	private static final String NAME = "BurpSiteTree";
	private static final String PREF_ENABLE_HOTKEY = "enableHotkey";
	private MontoyaApi api;
	private Registration copyHotkeyRegistration;
	private Registration openHotkeyRegistration;

	@Override
	public void initialize(MontoyaApi api) {
		this.api = api;
		api.extension().setName(NAME);
		api.logging().logToOutput(NAME + " Load OK");
		api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
			@Override
			public List<Component> provideMenuItems(ContextMenuEvent event) {
				JMenuItem copyMenu = new JMenuItem("Copy to clipboard");
				JMenuItem openMenu = new JMenuItem("Open in Editor");
				copyMenu.addActionListener(e -> copyAction(getRequestResponses(event)));
				openMenu.addActionListener(e -> openAction(getRequestResponses(event)));
				// Proxy HTTP Historyのみホットキーを表示する
				if (getBooleanPreference(PREF_ENABLE_HOTKEY, true)
						&& event.toolType() == ToolType.PROXY) {
					copyMenu.setAccelerator(KeyStroke.getKeyStroke("ctrl shift C"));
					openMenu.setAccelerator(KeyStroke.getKeyStroke("ctrl shift E"));
				}
				return List.of(copyMenu, openMenu);
			}
		});
		api.userInterface().registerSettingsPanel(new SettingsPanel() {
			private final JPanel panel = createSettingsPanel();

			@Override
			public JComponent uiComponent() {
				return panel;
			}
		});
		updateHotkeys(getBooleanPreference(PREF_ENABLE_HOTKEY, true));
	}

	private JPanel createSettingsPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		JLabel title = new JLabel(NAME);
		JLabel description = new JLabel("Enable or disable keyboard shortcuts.");
		JCheckBox enableHotkey = new JCheckBox("Enable Hotkey",
				getBooleanPreference(PREF_ENABLE_HOTKEY, true));
		title.setFont(title.getFont().deriveFont(Font.BOLD, 16f));
		title.setAlignmentX(Component.LEFT_ALIGNMENT);
		description.setAlignmentX(Component.LEFT_ALIGNMENT);
		enableHotkey.setAlignmentX(Component.LEFT_ALIGNMENT);
		enableHotkey.addActionListener(e -> {
			boolean enabled = enableHotkey.isSelected();
			setBooleanPreference(PREF_ENABLE_HOTKEY, enabled);
			updateHotkeys(enabled);
		});
		panel.add(title);
		panel.add(Box.createVerticalStrut(8));
		panel.add(description);
		panel.add(Box.createVerticalStrut(16));
		panel.add(enableHotkey);
		return panel;
	}

	// ホットキーは Proxy HTTP History のみ対応
	private void updateHotkeys(boolean enabled) {
		if (copyHotkeyRegistration != null) {
			copyHotkeyRegistration.deregister();
			copyHotkeyRegistration = null;
		}
		if (openHotkeyRegistration != null) {
			openHotkeyRegistration.deregister();
			openHotkeyRegistration = null;
		}
		if (enabled) {
			copyHotkeyRegistration = api.userInterface().registerHotKeyHandler(
					HotKeyContext.PROXY_HTTP_HISTORY,
					HotKey.hotKey("Copy to clipboard", "Ctrl+Shift+C"),
					event -> copyAction(event.selectedRequestResponses()));
			openHotkeyRegistration = api.userInterface().registerHotKeyHandler(
					HotKeyContext.PROXY_HTTP_HISTORY,
					HotKey.hotKey("Open in Editor", "Ctrl+Shift+E"),
					event -> openAction(event.selectedRequestResponses()));
		}
	}

	private boolean getBooleanPreference(String key, boolean defaultValue) {
		String value = api.persistence().preferences().getString(NAME + "." + key);
		return value == null ? defaultValue : Boolean.parseBoolean(value);
	}

	private void setBooleanPreference(String key, boolean value) {
		api.persistence().preferences().setString(NAME + "." + key, Boolean.toString(value));
	}

	// Proxy HTTP History と Repeater の双方に対応
	private List<HttpRequestResponse> getRequestResponses(ContextMenuEvent event) {
		List<HttpRequestResponse> messages = event.selectedRequestResponses();
		if (!messages.isEmpty()) {
			return messages;
		}
		var editorMessage = event.messageEditorRequestResponse();
		if (editorMessage.isPresent()) {
			return List.of(editorMessage.get().requestResponse());
		}
		return List.of();
	}

	// 選択したリクエスト情報をクリップボードへコピー
	private void copyAction(List<HttpRequestResponse> messages) {
		if (messages == null || messages.isEmpty()) {
			return;
		}
		try {
			String text = StringUtils.edit(messages);
			Toolkit toolkit = Toolkit.getDefaultToolkit();
			Clipboard clipboard = toolkit.getSystemClipboard();
			StringSelection selection = new StringSelection(text);
			clipboard.setContents(selection, selection);
		} catch (Exception e) {
			api.logging().logToError(e.toString());
		}
	}

	// 選択したリクエスト情報をテキストファイルとして開く
	private void openAction(List<HttpRequestResponse> messages) {
		if (messages == null || messages.isEmpty()) {
			return;
		}
		try {
			String text = StringUtils.edit(messages);
			File file = File.createTempFile(NAME, ".txt");
			file.deleteOnExit();
			try (FileOutputStream fs = new FileOutputStream(file)) {
				fs.write(text.getBytes(StandardCharsets.UTF_8));
			}
			Desktop.getDesktop().open(file);
		} catch (Exception e) {
			api.logging().logToError(e.toString());
		}
	}
}
