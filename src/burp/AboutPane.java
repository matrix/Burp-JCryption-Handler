package burp;

import javax.swing.JPanel;
import javax.swing.JLabel;

import javax.swing.ImageIcon;

import java.awt.Color;
import java.awt.Desktop;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;

public class AboutPane extends JPanel {

	private static final long serialVersionUID = 1L;

	public AboutPane() {

		setLayout(null);

		JLabel lbl_name = new JLabel("Name");
		lbl_name.setBounds(104, 31, 48, 22);
		add(lbl_name);

		JLabel lbl_name_value = new JLabel(BurpExtender.EXTENSION_NAME);
		lbl_name_value.setBounds(178, 31, 443, 22);
		add(lbl_name_value);

		JLabel lbl_version = new JLabel("Version");
		lbl_version.setBounds(93, 58, 61, 22);
		add(lbl_version);

		JLabel lbl_version_value = new JLabel(BurpExtender.EXTENSION_VERSION);
		lbl_version_value.setBounds(178, 58, 443, 22);
		add(lbl_version_value);

		JLabel lbl_author = new JLabel("Author");
		lbl_author.setBounds(96, 85, 56, 22);
		add(lbl_author);

		JLabel lbl_author_value = new JLabel(BurpExtender.EXTENSION_AUTHOR);
		lbl_author_value.setBounds(178, 85, 443, 22);
		add(lbl_author_value);

		JLabel lbl_development = new JLabel("Development");
		lbl_development.setBounds(63, 112, 109, 22);
		add(lbl_development);

		JLabel lbl_development_value = new JLabel(BurpExtender.EXTENSION_URL);
		lbl_development_value.setBounds(178, 112, 443, 22);
		lbl_development_value.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
				if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
					try {
						desktop.browse(new URL(BurpExtender.EXTENSION_URL).toURI());
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				}
			}
		});
		lbl_development_value.setForeground(Color.BLUE);
		add(lbl_development_value);

		URL url = getClass().getResource(BurpExtender.EXTENSION_IMG);
		if (url != null)
		{
			ImageIcon imageIcon = new ImageIcon(url);
			JLabel lbl_image = new JLabel(imageIcon);
			lbl_image.setBounds(178, 146, 180, 108);
			add(lbl_image);
		}
	}
}
