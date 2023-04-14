package burp;

import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.List;
import java.util.ArrayList;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	static final String name = "BurpSiteTree";
	static PrintWriter stdout;
	static PrintWriter stderr;
	static IBurpExtenderCallbacks callbacks;

	// implement IBurpExtender
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		callbacks.setExtensionName(BurpExtender.name);
		callbacks.registerContextMenuFactory(this);
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);
		stdout.println(BurpExtender.name + " Load OK");
	}

	// implement IContextMenuFactory
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuList = new ArrayList<>();
		JMenuItem menuItem1 = new JMenuItem("Copy to clipboard");
		JMenuItem menuItem2 = new JMenuItem("Open in Editor");
		menuItem1.addActionListener(e -> copyAction(invocation.getSelectedMessages()));
		menuItem2.addActionListener(e -> openAction(invocation.getSelectedMessages()));
		menuList.add(menuItem1);
		menuList.add(menuItem2);
		return menuList;
	}

	// copy to clipboard
	private void copyAction(IHttpRequestResponse[] messages) {
		if (messages == null) {
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
		if (messages == null) {
			return;
		}
		try {
			String text = StringUtils.edit(messages);
			File file = File.createTempFile(BurpExtender.name, ".txt");
			file.deleteOnExit();
			try (FileOutputStream fs = new FileOutputStream(file, true)) {
				fs.write(text.getBytes());
				Desktop desktop = Desktop.getDesktop();
				desktop.open(file);
			} catch (Exception ex) {
				ex.printStackTrace(stderr);
			}
		} catch (Exception ex) {
			ex.printStackTrace(stderr);
		}
	}
}
