package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import java.awt.Component;
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.swing.JMenuItem;

public class BurpExtender implements BurpExtension {
	private static final String NAME = "BurpSiteTree";
	private MontoyaApi api;

	@Override
	public void initialize(MontoyaApi api) {
		this.api = api;
		api.extension().setName(NAME);
		api.logging().logToOutput(NAME + " Load OK");
		api.userInterface().registerContextMenuItemsProvider(
				new ContextMenuItemsProvider() {
					@Override
					public List<Component> provideMenuItems(ContextMenuEvent event) {
						JMenuItem copyMenu = new JMenuItem("Copy to clipboard");
						JMenuItem openMenu = new JMenuItem("Open in Editor");
						copyMenu.addActionListener(e -> copyAction(event.selectedRequestResponses()));
						openMenu.addActionListener(e -> openAction(event.selectedRequestResponses()));
						return List.of(copyMenu, openMenu);
					}
				});
	}

	// copy to clipboard
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
		} catch (Exception ex) {
			api.logging().logToError(ex.toString());
		}
	}

	// open in editor
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
		} catch (Exception ex) {
			api.logging().logToError(ex.toString());
		}
	}
}
