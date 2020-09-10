package examples;

import api.BlindsendAPI;
import blindsend.FileReceiver;
import blindsend.FileSender;
import org.apache.logging.log4j.LogManager;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Runnable example for sending files via blindsend
 * When run, the example will generate file sharing link, encrypt a file, and upload it to blindsend.
 */
public class BlindsendFileSendingExample {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(BlindsendFileSendingExample.class.getName());

    public static void main(String[] args) {
        Path fileToSendPath = Paths.get("src/main/resources/files/pcr.pdf");
        BlindsendAPI api = new BlindsendAPI("https://blindsend.tech/api");
        FileReceiver receiver = new FileReceiver(api);
        FileSender sender = new FileSender(api);

        URL link = null;
        try {
            link = receiver.getLink("mypass");
            sender.encryptAndSendFile(
                    link,
                    fileToSendPath
            );
            LOGGER.info("Blindsend file exchange link: " + link.toString());
        } catch (NoSuchAlgorithmException e) {
            Logger.getLogger(BlindsendFileSendingExample.class.getName()).log(Level.SEVERE, "NoSuchAlgorithmException", e);
        } catch (InvalidKeySpecException e) {
            Logger.getLogger(BlindsendFileSendingExample.class.getName()).log(Level.SEVERE, "InvalidKeySpecException", e);
        } catch (IOException e) {
            Logger.getLogger(BlindsendFileSendingExample.class.getName()).log(Level.SEVERE, "IOException", e);
        } catch (GeneralSecurityException e) {
            Logger.getLogger(BlindsendFileSendingExample.class.getName()).log(Level.SEVERE, "GeneralSecurityException", e);
        } catch (NullPointerException e) {
            Logger.getLogger(BlindsendFileSendingExample.class.getName()).log(Level.SEVERE, "NullPointerException", e);
        }
    }
}
