package burp;

import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	private static final String NAME = "BurpSiteTree";
	static PrintWriter stdout;
	static PrintWriter stderr;
	static IExtensionHelpers helpers;

	// implement IBurpExtender
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.helpers = callbacks.getHelpers();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);
		stdout.println(NAME + " Load OK");
	}

	// implement IContextMenuFactory
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		JMenuItem copyMenu = new JMenuItem("Copy to clipboard");
		JMenuItem openMenu = new JMenuItem("Open in Editor");
		copyMenu.addActionListener(e -> copyAction(invocation.getSelectedMessages()));
		openMenu.addActionListener(e -> openAction(invocation.getSelectedMessages()));
		return List.of(copyMenu, openMenu);
	}

	// copy to clipboard
	private void copyAction(IHttpRequestResponse[] messages) {
		if (messages == null || messages.length == 0) {
			return;
		}
		try {
			String text = StringUtils.edit(messages);
			Toolkit toolkit = Toolkit.getDefaultToolkit();
			Clipboard clipboard = toolkit.getSystemClipboard();
			StringSelection selection = new StringSelection(text);
			clipboard.setContents(selection, selection);
		} catch (Exception ex) {
			ex.printStackTrace(stderr);
		}
	}

	// open in editor
	private void openAction(IHttpRequestResponse[] messages) {
		if (messages == null || messages.length == 0) {
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
			ex.printStackTrace(stderr);
		}
	}
}
