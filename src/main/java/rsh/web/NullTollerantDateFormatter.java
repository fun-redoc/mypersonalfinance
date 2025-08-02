package rsh.web;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.SimpleFormatter;

public record NullTollerantDateFormatter(SimpleDateFormat simpleDateFormatter) {
    public String format(Date date) {
        if(date != null) {
            var formatedDate = simpleDateFormatter.format(date);
            return formatedDate;
        } else {
            return null;
        }
    }
    public String format(boolean catchMe,Date date) {
        if(date != null) {
            var formatedDate = simpleDateFormatter.format(date);
            return formatedDate;
        } else {
            return null;
        }
    }
}
