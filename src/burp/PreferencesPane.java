package burp;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JToggleButton;

import javax.swing.JTextField;
import javax.swing.JSeparator;
import javax.swing.JButton;
import java.awt.event.ItemListener;
import java.awt.event.ItemEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class PreferencesPane extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextField txt_parameter_value;
	private JTextField txt_passphrase_value;
	private boolean isEnabled;
	private IBurpExtenderCallbacks callbacks;

	public PreferencesPane(IBurpExtenderCallbacks icallbacks) {

		this.callbacks = icallbacks;

		setLayout(null);

		JSeparator separator = new JSeparator();
		separator.setBounds(0, 0, 1, 1);
		add(separator);

		JToggleButton tglbtn_status = new JToggleButton("Disable");
		tglbtn_status.setBounds(194, 44, 76, 29);
		tglbtn_status.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED)
				{
					tglbtn_status.setText("Disable");
					isEnabled = true;
				}
				else
				{
					tglbtn_status.setText("Enable");
					isEnabled = false;
				}
			}
		});

		JLabel lbl_status = new JLabel("Status");
		lbl_status.setBounds(108, 50, 73, 16);
		add(lbl_status);
		tglbtn_status.setSelected(true);
		add(tglbtn_status);

		JLabel lbl_parameter = new JLabel("Parameter");
		lbl_parameter.setBounds(85, 125, 83, 16);
		add(lbl_parameter);

		txt_parameter_value = new JTextField();
		txt_parameter_value.setBounds(194, 120, 256, 26);
		txt_parameter_value.setText(BurpExtender.getParameter());
		add(txt_parameter_value);
		txt_parameter_value.setColumns(10);

		JLabel lbl_passphrase = new JLabel("Passphrase");
		lbl_passphrase.setBounds(77, 156, 86, 16);
		add(lbl_passphrase);

		JButton btn_save = new JButton("Save");
		btn_save.setBounds(390, 188, 60, 31);
		btn_save.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String tmp1 = txt_parameter_value.getText();
				if (tmp1.length() > 0)
				{
					BurpExtender.setParameter(tmp1);
					callbacks.saveExtensionSetting("JCryption_lastParameter", tmp1);
				}

				String tmp2 = txt_passphrase_value.getText();
				if (tmp2.length() > 0)
				{
					BurpExtender.setPassphrase(tmp2.getBytes());
					callbacks.saveExtensionSetting("JCryption_lastPassphrase", tmp2);
				}
			}
		});

		txt_passphrase_value = new JTextField();
		txt_passphrase_value.setBounds(194, 151, 256, 26);
		txt_passphrase_value.setText(new String(BurpExtender.getPassphrase()));
		add(txt_passphrase_value);
		txt_passphrase_value.setColumns(10);
		add(btn_save);

		isEnabled = true;
	}

	public boolean getPluginStatus()
	{
		return this.isEnabled;
	}

	public void setPassphrase(String p)
	{
		this.txt_passphrase_value.setText(p);
	}
}
