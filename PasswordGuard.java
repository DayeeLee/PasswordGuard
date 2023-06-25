import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.Key;
import java.util.Base64;

public class PasswordGuard {
    private static final String SECRET_KEY = "12345678901234567890123456789012"; //32bit
    private static final String IV_STRING = "1234567890123456"; //16bit

    private JFrame frame;
    private JTextField inputTextField;
    private JTextField codeTextField;
    private JTextArea resultTextArea;

    public PasswordGuard() {
        frame = new JFrame("SecureSaltEncryptor");

        // Create input field for password
        JLabel inputLabel = new JLabel("Enter password:");
        inputTextField = new JTextField(20);
        inputLabel.setLabelFor(inputTextField);

        // Create input field for code
        JLabel codeLabel = new JLabel("Enter code:");
        codeTextField = new JTextField(20);
        codeLabel.setLabelFor(codeTextField);

        // Create encrypt button
        JButton encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String password = inputTextField.getText();
                    String code = codeTextField.getText();
                    String original = password + "::" + code;
                    String encrypted = encryptAES256(original, SECRET_KEY);
                    resultTextArea.setText("Encrypted: " + encrypted);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

// Create decrypt button
        JButton decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String encrypted = inputTextField.getText();
                    String decrypted = decryptAES256(encrypted, SECRET_KEY);
                    String password = decrypted.split("::")[0];  // The password is before the "::"
                    String code = decrypted.split("::")[1];  // The code is after the "::"
                    resultTextArea.setText("Decrypted: Password - " + password + ", Code - " + code);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });



        // Create text area for output
        resultTextArea = new JTextArea(10, 20);
        resultTextArea.setEditable(false);

        // Add components to frame
        frame.setLayout(new FlowLayout());
        frame.add(inputLabel);
        frame.add(inputTextField);
        frame.add(codeLabel);
        frame.add(codeTextField);
        frame.add(encryptButton);
        frame.add(decryptButton);
        frame.add(new JScrollPane(resultTextArea));
        frame.setSize(500, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    public void show() {
        frame.setVisible(true);
    }

    public static void main(String[] args) {
        new PasswordGuard().show();
    }

    private Key getAESKey(String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(makeKey(key).getBytes(), "AES");
        return keySpec;
    }

    private String makeKey(String str) throws UnsupportedEncodingException {
        byte[] keyBytes = new byte[32];
        byte[] parameterKeyBytes= str.getBytes("UTF-8");
        System.arraycopy(parameterKeyBytes, 0, keyBytes, 0, Math.min(parameterKeyBytes.length, keyBytes.length));
        return new String(keyBytes, "UTF-8");
    }

    // 암호화 메서드
    public String encryptAES256(String str, String key) {
        String encrypted = null;
        try {
            Key keySpec = getAESKey(key);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes()));
            byte[] encryptedBytes = c.doFinal(str.getBytes());
            encrypted = Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    // 복호화 메서드
    public String decryptAES256(String encrypted, String key) {
        String decrypted = null;
        try {
            Key keySpec = getAESKey(key);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes()));
            byte[] byteStr = Base64.getDecoder().decode(encrypted);
            decrypted = new String(c.doFinal(byteStr));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypted;
    }

}
