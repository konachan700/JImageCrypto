
package imagecrypto;

import java.awt.Container;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.MediaTracker;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JProgressBar;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jdesktop.application.Action;
//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;

public class imageOne extends javax.swing.JFrame {
    int prewievSize = 130;
    int totalBytes = 0;
    int saveWODialog = 0;
    JProgressBar jpb1 = null;
    
    String data_md5_sign = null;
    
    boolean DBG1 = false;

    public imageOne() {
        initComponents();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jPasswordField1 = new javax.swing.JPasswordField();
        jLabel2 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jTextField2 = new javax.swing.JTextField();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jProgressBar1 = new javax.swing.JProgressBar();
        jButton1 = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jButton4 = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(imagecrypto.ImageCryptoApp.class).getContext().getResourceMap(imageOne.class);
        setTitle(resourceMap.getString("Form.title")); // NOI18N
        setName("Form"); // NOI18N
        setResizable(false);

        jTabbedPane1.setName("jTabbedPane1"); // NOI18N

        jPanel1.setName("jPanel1"); // NOI18N

        jLabel1.setBackground(resourceMap.getColor("jLabel1.background")); // NOI18N
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jLabel1.setName("jLabel1"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTextArea1.setColumns(20);
        jTextArea1.setFont(resourceMap.getFont("jTextArea1.font")); // NOI18N
        jTextArea1.setLineWrap(true);
        jTextArea1.setRows(5);
        jTextArea1.setWrapStyleWord(true);
        jTextArea1.setName("jTextArea1"); // NOI18N
        jTextArea1.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                jTextArea1KeyTyped(evt);
            }
        });
        jScrollPane1.setViewportView(jTextArea1);

        jPasswordField1.setName("jPasswordField1"); // NOI18N

        jLabel2.setText(resourceMap.getString("jLabel2.text")); // NOI18N
        jLabel2.setName("jLabel2"); // NOI18N

        jTextField1.setEditable(false);
        jTextField1.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jTextField1.setName("jTextField1"); // NOI18N

        jTextField2.setEditable(false);
        jTextField2.setText(resourceMap.getString("jTextField2.text")); // NOI18N
        jTextField2.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jTextField2.setMargin(new java.awt.Insets(1, 3, 1, 1));
        jTextField2.setName("jTextField2"); // NOI18N

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(imagecrypto.ImageCryptoApp.class).getContext().getActionMap(imageOne.class, this);
        jButton2.setAction(actionMap.get("save_image_file")); // NOI18N
        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setEnabled(false);
        jButton2.setName("jButton2"); // NOI18N

        jButton3.setAction(actionMap.get("open_image_file")); // NOI18N
        jButton3.setName("jButton3"); // NOI18N

        jProgressBar1.setName("jProgressBar1"); // NOI18N
        jProgressBar1.setStringPainted(true);

        jButton1.setAction(actionMap.get("quit")); // NOI18N
        jButton1.setName("jButton1"); // NOI18N

        jLabel3.setForeground(resourceMap.getColor("jLabel3.foreground")); // NOI18N
        jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
        jLabel3.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        jLabel3.setName("jLabel3"); // NOI18N

        jButton4.setAction(actionMap.get("save_wo_dialog")); // NOI18N
        jButton4.setText(resourceMap.getString("jButton4.text")); // NOI18N
        jButton4.setEnabled(false);
        jButton4.setName("jButton4"); // NOI18N

        jLabel4.setText(resourceMap.getString("jLabel4.text")); // NOI18N
        jLabel4.setName("jLabel4"); // NOI18N

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 516, Short.MAX_VALUE)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
                            .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jTextField1, javax.swing.GroupLayout.DEFAULT_SIZE, 238, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jButton3))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                        .addGap(33, 33, 33)
                                        .addComponent(jLabel2))
                                    .addComponent(jProgressBar1, javax.swing.GroupLayout.DEFAULT_SIZE, 89, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jPasswordField1)
                                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                        .addComponent(jButton4)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton2))))))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jTextField2, javax.swing.GroupLayout.DEFAULT_SIZE, 423, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton1)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jButton3)
                            .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel4)
                        .addGap(26, 26, 26)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jButton4)
                            .addComponent(jProgressBar1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButton2))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel2)))
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 142, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 99, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1))
                .addContainerGap())
        );

        jTabbedPane1.addTab(resourceMap.getString("jPanel1.TabConstraints.tabTitle"), jPanel1); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 541, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 325, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jTextArea1KeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_jTextArea1KeyTyped
        jTextField2.setText("Всего емкость: " + totalBytes + " байт; использовано " + jTextArea1.getText().length() + " байт");
    }//GEN-LAST:event_jTextArea1KeyTyped

    public static void main(String args[]) {
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new imageOne().setVisible(true);
            }
        });
    }

    //==================================================================================================
    //==================================================================================================
    
    private void __set_progress_indicator(JProgressBar j) {
        jpb1 = j;
        return;
    }
      
    private ByteArrayOutputStream __decompress_byte_array(byte[] array) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte tb = 0;
        if (jpb1 != null) jpb1.setMaximum(array.length);
        for (int i=0; i<array.length; i++) {
            for (int j=0; j<8; j++) {
                tb = array[i];
                tb = (byte) (tb << j);
                tb = (byte) (tb >> 7);
                baos.write((tb == 0) ? 0 : 1);
            }
            if (jpb1 != null) {
                jpb1.setValue(i);
                jpb1.setString("decompress: " + i + " of " + array.length); 
            }
        }
        if (jpb1 != null) { jpb1.setValue(0); jpb1.setString("0%"); }
        return baos;
    }
    
    private ByteArrayOutputStream __compress_byte_array(byte[] array) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int ti = 0;
        if (jpb1 != null) jpb1.setMaximum(array.length);
        for (int s=0; s<array.length; s=s+8) {
            try {
                ti = Integer.parseInt("" + array[s]   + array[s+1] + array[s+2] + array[s+3]
                                         + array[s+4] + array[s+5] + array[s+6] + array[s+7], 2);
            } catch (ArrayIndexOutOfBoundsException e) {
                break;
            }
            baos.write(ti);
            if (jpb1 != null) {
                jpb1.setValue(s);
                jpb1.setString("compress: " + s + " of " + array.length); 
            }
        }
        if (jpb1 != null) { jpb1.setValue(0); jpb1.setString("0%"); }
        return baos;
    }
    
    private int __get_l_header(BufferedImage image) {
        int r = 0;
        int g = 0; 
        int b = 0;
        int h = image.getHeight();
        int w = image.getWidth();
        int c = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteArrayOutputStream sign = new ByteArrayOutputStream();
        
        for (int y=0; y<27; y++) {
            c = image.getRGB(0, y);
            r = (c >> 16);
            g = (c >> 8);
            b = (c);
            baos.write(((r & 1) == 0) ? 0 : 1); 
            baos.write(((g & 1) == 0) ? 0 : 1);
            if (y<26) baos.write(((b & 1) == 0) ? 0 : 1);
        }
        
        for (int j=26; j<70; j++) {
            c = image.getRGB(0, j);
            r = (c >> 16);
            g = (c >> 8);
            b = (c);
            if (j>26) sign.write(((r & 1) == 0) ? 0 : 1); 
            if (j>26) sign.write(((g & 1) == 0) ? 0 : 1);
            sign.write(((b & 1) == 0) ? 0 : 1);
        }
        data_md5_sign = new BigInteger(1, __compress_byte_array(sign.toByteArray()).toByteArray()).toString(16).toUpperCase();

        ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
        baos2 = __compress_byte_array(baos.toByteArray());
        int sl = 0;
        try {
            sl = Integer.parseInt(baos2.toString(), 10);
        } catch (NumberFormatException e) {
            return 0;
        }
        return sl;
    }
    
    private ByteArrayOutputStream __get_bytes_array_from_image(BufferedImage image) {
        int count_byte = (__get_l_header(image) + 10 + 16) * 8;
        int counter = 0;
        int r = 0;
        int g = 0; 
        int b = 0;
        int h = image.getHeight();
        int w = image.getWidth();
        int c = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (jpb1 != null) jpb1.setMaximum((w * h) + 1);
        
        for (int x=0; x<w; x++) {
            for (int y=0; y<h; y++) {
                c = image.getRGB(x, y);
                r = (c >> 16);
                g = (c >> 8);
                b = (c);
                if (count_byte >= counter) baos.write(((r & 1) == 0) ? 0 : 1);
                counter++;
                if (count_byte >= counter) baos.write(((g & 1) == 0) ? 0 : 1);
                counter++;
                if (count_byte >= counter) baos.write(((b & 1) == 0) ? 0 : 1);
                counter++;
                if (jpb1 != null) {
                    jpb1.setValue(jpb1.getValue() + 1);
                    jpb1.setString("read: " + counter + " bits"); 
                }
            }
        }
        if (jpb1 != null) { jpb1.setValue(0); jpb1.setString("0%"); }
        return baos;
    }
    
    private ByteArrayOutputStream __prepare_text(String text, byte[] pass) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte t2[] = text.getBytes();
        byte temp[] = (pass == null) ? t2 : __AESCrypt(t2, pass);
        String text_size = "0000000000" + temp.length;
        text_size = text_size.substring(text_size.length() - 10, text_size.length());
        byte text_md5[] = __bMD5(t2);
        baos.write(text_size.getBytes(), 0, text_size.length());
        baos.write(text_md5, 0, text_md5.length);
        baos.write(temp, 0, temp.length);
        ByteArrayOutputStream ret_baos = new ByteArrayOutputStream();
        ret_baos = __decompress_byte_array(baos.toByteArray());
        baos.reset();
        return ret_baos;
    }
    
    private BufferedImage __write_to_image(BufferedImage image, byte[] array) {
        int r = 0;
        int g = 0; 
        int b = 0;
        int mask_r = 0x010000;
        int mask_g = 0x0100;
        int mask_b = 0x01;
        
        int counter = 0;
        int count_a = array.length;
        int h = image.getHeight();
        int w = image.getWidth();
        int c = 0;
        
        if (jpb1 != null) jpb1.setMaximum((w * h) + 1);
        for (int x=0; x<w; x++) {
            for (int y=0; y<h; y++) {
                try {
                    c = image.getRGB(x, y);
                    
                    if (count_a > counter) { 
                        r = array[counter];
                        if (r == 0) c = c & ~mask_r; else c = c | mask_r;
                        counter++;
                    }
                    
                    if (count_a > counter) { 
                        g = array[counter];
                        if (g == 0) c = c & ~mask_g; else c = c | mask_g;
                        counter++;
                    }
                    
                    if (count_a > counter) { 
                        b = array[counter];
                        if (b == 0) c = c & ~mask_b; else c = c | mask_b;
                        counter++;
                    }

                    if (jpb1 != null) {
                        jpb1.setValue(jpb1.getValue() + 1);
                        jpb1.setString("save: " + counter + " bits"); 
                    }
                    
                    image.setRGB(x, y, c);
                } catch (ArrayIndexOutOfBoundsException e) {
                    break;
                }
            }
        }
        if (jpb1 != null) { jpb1.setValue(0); jpb1.setString("0%"); }
        return image;
    }
    
    private String __cut_text_from_baos(byte[] array, byte[] pass) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(array, 0, 10);
        int sl = 0;
        try {
            sl = Integer.parseInt(baos.toString(), 10);
        } catch (NumberFormatException e) { return null; }
        
        if (sl < 1) return null;
        baos.reset();

        ByteArrayOutputStream out_baos = new ByteArrayOutputStream();
        try {
            out_baos.write(array, 10 + 16, sl);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
        
        if (pass == null) {
            String t_md5 = new BigInteger(1, __bMD5(out_baos.toByteArray())).toString(16).toUpperCase();
              if (data_md5_sign.compareTo(t_md5) == 0)
                    return out_baos.toString().trim();
                else
                    return null;          
        } else {
             byte enc[] = __AESDecrypt(out_baos.toByteArray(), pass);
            if (enc == null) {
                return null;
            } else {
                ByteArrayOutputStream ret_baos = new ByteArrayOutputStream();
                ret_baos.write(enc, 0, enc.length);
                String t_md5 = new BigInteger(1, __bMD5(ret_baos.toByteArray())).toString(16).toUpperCase();
                if (data_md5_sign.compareTo(t_md5) == 0)
                    return ret_baos.toString().trim();
                else
                    return null;
            }
        }
    }
    
    private static byte[] __bMD5(byte[] unsafe) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(unsafe);
            return md.digest();
        } catch (NoSuchAlgorithmException ex) { }
        return null;
    }

    private static byte[] __AES_Encrypt(byte[] value, byte[] password) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] pwd = Arrays.copyOf(__bMD5(password), 16);
        SecretKey key = new SecretKeySpec(pwd, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(value);
        return encrypted;
    }
    
    private static byte[] __AES_Decrypt(byte[] value, byte[] password) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] pwd = Arrays.copyOf(__bMD5(password), 16);
        SecretKey key = new SecretKeySpec(pwd, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(value);
        return decrypted;
    }
    
    private byte[] __AESDecrypt(byte[] value, byte[] password) {
        try {
            return __AES_Decrypt(value, password);
        } 
        catch (UnsupportedEncodingException ex)     { if (DBG1) System.out.println("__AESDecrypt: UnsupportedEncodingException"); } 
        catch (NoSuchAlgorithmException ex)         { if (DBG1) System.out.println("__AESDecrypt: NoSuchAlgorithmException"    ); } 
        catch (NoSuchProviderException ex)          { if (DBG1) System.out.println("__AESDecrypt: NoSuchProviderException"     ); } 
        catch (NoSuchPaddingException ex)           { if (DBG1) System.out.println("__AESDecrypt: NoSuchProviderException"     ); } 
        catch (InvalidKeyException ex)              { if (DBG1) System.out.println("__AESDecrypt: InvalidKeyException"         ); } 
        catch (IllegalBlockSizeException ex)        { if (DBG1) System.out.println("__AESDecrypt: IllegalBlockSizeException"   ); } 
        catch (BadPaddingException ex)              { if (DBG1) System.out.println("__AESDecrypt: BadPaddingException"         ); }
        return null;
    }
    
    private byte[] __AESCrypt(byte[] value, byte[] password) {
        try {
            return __AES_Encrypt(value, password);
        } 
        catch (UnsupportedEncodingException ex)     { if (DBG1) System.out.println("__AESCrypt: UnsupportedEncodingException" ); } 
        catch (NoSuchAlgorithmException ex)         { if (DBG1) System.out.println("__AESCrypt: NoSuchAlgorithmException"     ); } 
        catch (NoSuchPaddingException ex)           { if (DBG1) System.out.println("__AESCrypt: NoSuchProviderException"      ); } 
        catch (NoSuchProviderException ex)          { if (DBG1) System.out.println("__AESCrypt: NoSuchProviderException"      ); } 
        catch (InvalidKeyException ex)              { if (DBG1) System.out.println("__AESCrypt: InvalidKeyException"          ); } 
        catch (IllegalBlockSizeException ex)        { if (DBG1) System.out.println("__AESCrypt: IllegalBlockSizeException"    ); } 
        catch (BadPaddingException ex)              { if (DBG1) System.out.println("__AESCrypt: BadPaddingException"          ); }
        return null;
    }
    
    //==================================================================================================
    //==================================================================================================

    private void __unlock_controls(boolean lock) {
        jButton2.setEnabled(lock);
        jButton4.setEnabled(lock);
        jButton1.setEnabled(lock);
        jButton3.setEnabled(lock);
        jLabel2.setEnabled(lock);
        jPasswordField1.setEnabled(lock);
        jTextField1.setEnabled(lock);
        jTextArea1.setEnabled(lock);
    }
    
    private void __unlock_controls_p(boolean lock) {
        jButton2.setEnabled(false);
        jButton4.setEnabled(false);
        jButton1.setEnabled(lock);
        jButton3.setEnabled(lock);
        jLabel2.setEnabled(lock);
        jPasswordField1.setEnabled(lock);
        jTextField1.setEnabled(lock);
        jTextArea1.setEnabled(false);
    }
    
    private Runnable open_thread = new Runnable() {
        public void run() {
            JFileChooser fileopen = new JFileChooser();
            FileNameExtensionFilter ff1 = new FileNameExtensionFilter("Image files", "png", "jpg", "jpeg");
            fileopen.setFileFilter(ff1);
            int ret = fileopen.showDialog(null, "Открыть файл");
            if (ret == 0) {
                File fl = fileopen.getSelectedFile();
                if ((fl.canRead()) && (fl.length() > 0)) {
                    jTextField1.setText(fl.getAbsolutePath());
                    try {
                        BufferedImage image = ImageIO.read(fl);
                        MediaTracker mediaTracker = new MediaTracker(new Container()); 
                        mediaTracker.addImage(image, 0); 
                        mediaTracker.waitForAll();

                        int wS = image.getWidth(null);
                        int hS = image.getHeight(null);

                        if ((wS <= prewievSize) || (hS <= prewievSize)) {
                            jTextField1.setText("");
                            jTextField2.setText("error: file too small");
                            image.flush();
                            __unlock_controls_p(true);
                            return;
                        } else {
                            totalBytes = (((wS*hS*3) / 8) - 80);
                            totalBytes = totalBytes - (totalBytes / 10);
                            if (DBG1) 
                                jTextField2.setText("file: [type: png; " + wS + " x " + hS + "; total: " + totalBytes + " bytes;]");
                            else
                                jTextField2.setText("Всего емкость: " + totalBytes + " байт; использовано " + jTextArea1.getText().length() + " байт");
                        }

                        if (wS > hS) {
                            double kS = wS / prewievSize;
                            double kM = hS / kS;
                            Icon icon = new ImageIcon(image.getScaledInstance(prewievSize, (int)Math.round(kM), Image.SCALE_SMOOTH));
                            jLabel1.setIcon(icon);
                        } else {
                            double kS = hS / prewievSize;
                            double kM = wS / kS;
                            Icon icon = new ImageIcon(image.getScaledInstance((int)Math.round(kM), prewievSize, Image.SCALE_SMOOTH));
                            jLabel1.setIcon(icon);
                        }

                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        baos = __get_bytes_array_from_image(image);

                        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                        bytes = __compress_byte_array(baos.toByteArray());
                        baos.reset();
                        
                        String text = "";
                        if (jPasswordField1.getPassword().length < 1) {
                            text = __cut_text_from_baos(bytes.toByteArray(), null);
                        } else {
                            String pass = new String(jPasswordField1.getPassword());
                            text = __cut_text_from_baos(bytes.toByteArray(), pass.getBytes("UTF-8"));  
                        }

                        if (text != null) {
                            jTextArea1.setText(text);
                        } else {
                            jTextField2.setText(" Неверный пароль или в картинке нет текста");
                            jTextArea1.setText("");
                        }
                        __unlock_controls(true);
                        bytes.reset();
                    } catch (IOException ex) {
                        __unlock_controls_p(true);
                        return;
                    } catch (InterruptedException ex) {
                        __unlock_controls_p(true);
                        return;
                    }
                } else {
                    __unlock_controls_p(true);
                    return;
                }
            } else {
                __unlock_controls_p(true);
                return;
            }
        }
    };
        
    @Action
    public void open_image_file() {
        __unlock_controls(false);
        __set_progress_indicator(jProgressBar1);
        new Thread(open_thread).start();
    }

    private Runnable save_thread = new Runnable() {
        public void run() {
            File fl = new File(jTextField1.getText().trim());
            if (fl.canRead() == false) {
                jTextField2.setText("error: no image selected");
                __unlock_controls(true);
                saveWODialog = 0;
                return;
            }
            
            String path = "";
            if (jTextField1.getText().trim().endsWith(".png") == false) {
                Object[] options = {"Сохранить как...", "Отмена"};
                int retval1 = JOptionPane.showOptionDialog(rootPane, "Файл не является картинкой в формате PNG, сохранение невозможно. Сохранить в формать PNG?", 
                                                                      "Сохранение файла", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[1]);
                if (retval1 == 0) {
                    saveWODialog = 0;
                } else {
                    saveWODialog = 0;
                    __unlock_controls(true);
                    return;
                }
            }

            if (saveWODialog == 0) {
                JFileChooser fileSave = new JFileChooser();
                FileNameExtensionFilter ff1 = new FileNameExtensionFilter("PNG images", "png");
                fileSave.setFileFilter(ff1);
                int ret = fileSave.showSaveDialog(null);
                if (ret != 0) {
                    jTextField2.setText("fileSave.showSaveDialog error: no image selected");
                    __unlock_controls(true);
                    saveWODialog = 0;
                    return;
                }
                path = fileSave.getSelectedFile().getAbsolutePath();
            } else if (saveWODialog == 1) {
                path = jTextField1.getText().trim();
            }
            
            if (path.endsWith(".png") == false) path = path + ".png";
            File f = new File(path);
            
            try {
                if (((f.createNewFile() == false) || (f.canWrite() == false)) && (saveWODialog == 0)) {
                    jTextField2.setText("error: cannot create output image");
                    __unlock_controls(true);
                    saveWODialog = 0;
                    return;
                }
            } catch (IOException ex) {
                jTextField2.setText("IOException error: cannot create output image");
                    __unlock_controls(true);
                    saveWODialog = 0;
                    return;
            }

            try {
                BufferedImage image = ImageIO.read(fl);
                MediaTracker mediaTracker = new MediaTracker(new Container()); 
                mediaTracker.addImage(image, 0); 
                mediaTracker.waitForAll();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                if (jPasswordField1.getPassword().length < 1) {
                    baos = __prepare_text(jTextArea1.getText(), null);
                } else {
                    String pass = new String(jPasswordField1.getPassword());
                    baos = __prepare_text(jTextArea1.getText(), pass.getBytes("UTF-8"));
                }

                image = __write_to_image(image, baos.toByteArray());
                ImageIO.write(image, "png", new FileOutputStream(path));
                __unlock_controls(true);
                jProgressBar1.setValue(0);

            } catch (IOException ex) {
                __unlock_controls(true);
                saveWODialog = 0;
                return;
            } catch (InterruptedException ex) {
                __unlock_controls(true);
                saveWODialog = 0;
                return;
            }
            saveWODialog = 0;
        }
    };    
    
    @Action
    public void save_image_file() {
        __set_progress_indicator(jProgressBar1);
        __unlock_controls(false);
        new Thread(save_thread).start();
    }

    @Action
    public void save_wo_dialog() {
        saveWODialog = 1;
        __set_progress_indicator(jProgressBar1);
        __unlock_controls(false);
        new Thread(save_thread).start();
    }
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPasswordField jPasswordField1;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    // End of variables declaration//GEN-END:variables
}
