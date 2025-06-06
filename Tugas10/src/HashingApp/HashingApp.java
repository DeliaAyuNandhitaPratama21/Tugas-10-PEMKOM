package HashingApp;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.encoders.Hex;
import org.mindrot.jbcrypt.BCrypt;
/**
 *
 * @author ASUS
 */
public class HashingApp extends JFrame {

    private JComboBox<String> hashMethod;
    private JTextArea inputArea;
    private JTextArea outputArea;
    private JButton hashButton, loadFileButton;

    public HashingApp() {
        setTitle("Hashing App - PBKDF2, bcrypt, scrypt");
        setSize(600, 500);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        hashMethod = new JComboBox<>(new String[]{"PBKDF2", "bcrypt", "scrypt"});
        inputArea = new JTextArea(8, 40);
        outputArea = new JTextArea(6, 40);
        outputArea.setEditable(false);

        hashButton = new JButton("Hash Input");
        loadFileButton = new JButton("Load File");

        JPanel topPanel = new JPanel(new FlowLayout());
        topPanel.add(new JLabel("Hash Method:"));
        topPanel.add(hashMethod);
        topPanel.add(loadFileButton);
        topPanel.add(hashButton);

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.add(new JLabel("Input Text/File Content:"), BorderLayout.NORTH);
        inputPanel.add(new JScrollPane(inputArea), BorderLayout.CENTER);

        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.add(new JLabel("Hashed Output:"), BorderLayout.NORTH);
        outputPanel.add(new JScrollPane(outputArea), BorderLayout.CENTER);

        setLayout(new BorderLayout());
        add(topPanel, BorderLayout.NORTH);
        add(inputPanel, BorderLayout.CENTER);
        add(outputPanel, BorderLayout.SOUTH);

        loadFileButton.addActionListener(e -> loadFile());
        hashButton.addActionListener(e -> hashInput());
    }

    private void loadFile() {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                inputArea.setText(content);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Gagal membaca file.");
            }
        }
    }

    private void hashInput() {
        String input = inputArea.getText();
        String method = (String) hashMethod.getSelectedItem();

        if (input.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Input tidak boleh kosong.");
            return;
        }

        String result = switch (method) {
            case "PBKDF2" -> hashPBKDF2(input);
            case "bcrypt" -> hashBCrypt(input);
            case "scrypt" -> hashScrypt(input);
            default -> "Metode tidak dikenali.";
        };

        outputArea.setText(result);
    }

    private String hashPBKDF2(String input) {
        try {
            byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
            PBEKeySpec spec = new PBEKeySpec(input.toCharArray(), salt, 65536, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return "Salt (Base64): " + Base64.getEncoder().encodeToString(salt) + "\n"
                 + "Hash (Base64): " + Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return "Error hashing dengan PBKDF2.";
        }
    }

    private String hashBCrypt(String input) {
        String hash = BCrypt.hashpw(input, BCrypt.gensalt(12));
        return "Hash: " + hash;
    }

    private String hashScrypt(String input) {
        try {
            byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
            byte[] hash = SCrypt.generate(input.getBytes(StandardCharsets.UTF_8), salt, 16384, 8, 1, 32);
            return "Salt (Hex): " + Hex.toHexString(salt) + "\n"
                 + "Hash (Hex): " + Hex.toHexString(hash);
        } catch (Exception e) {
            return "Error hashing dengan scrypt.";
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new HashingApp().setVisible(true));
    }
}
