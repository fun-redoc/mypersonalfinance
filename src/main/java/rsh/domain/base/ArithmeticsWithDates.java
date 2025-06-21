package rsh.domain.base;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class ArithmeticsWithDates {

    public static Date min(Date d1, Date d2) {
        return d1.before(d2) ? d1 : d2;
    }

    public static Date max(Date d1, Date d2) {
        return d1.after(d2) ? d1 : d2;
    }

    public static long daysInYear(int year) {
        Calendar calendar = Calendar.getInstance();
        calendar.set(year, Calendar.DECEMBER, 31);
        return calendar.get(Calendar.DAY_OF_YEAR);
    }

    public static double calculateFractionOfYear(Date start, Date end) {
        // Calculate the year of the start date
        Calendar startCalendar = Calendar.getInstance();
        startCalendar.setTime(start);
        int startYear = startCalendar.get(Calendar.YEAR);

        // Get the total number of days in the start year
        long daysInYear = ArithmeticsWithDates.daysInYear(startYear);

        // Difference in milliseconds
        long differenceInMillis = end.getTime() - start.getTime();

        // Convert milliseconds to days
        long differenceInDays = differenceInMillis / (24 * 60 * 60 * 1000L);

        // Calculate the fraction
        return (double) differenceInDays / daysInYear;
    }

    public record DateInterval(Date begin, Date end){}
    public static List<DateInterval> splitIntervalByYear(Date start, Date end) {
        List<DateInterval> intervals = new ArrayList<>();
        Calendar calendar = Calendar.getInstance();

        // Initialize the current start date
        calendar.setTime(start);

        while (calendar.getTime().before(end)) {
            // Get the start date for the current interval
            Date intervalStart = calendar.getTime();

            // Move to the end of the current year
            calendar.set(Calendar.MONTH, Calendar.DECEMBER);
            calendar.set(Calendar.DAY_OF_MONTH, 31);

            // Ensure the interval end doesn't exceed the overall end date
            Date intervalEnd = calendar.getTime().before(end) ? calendar.getTime() : end;

            // Add the interval to the list
            intervals.add(new DateInterval(intervalStart, intervalEnd));

            // Move to the start of the next year
            calendar.add(Calendar.DAY_OF_YEAR, 1); // January 1 of the next year
        }

        return intervals;
    }
}
