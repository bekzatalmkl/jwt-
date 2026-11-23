package kz.bekzat.jwt.analytics;

import kz.bekzat.jwt.dao.SecurityEventDao;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class SecurityAnalyticsService {

    private final SecurityEventDao dao;

    public SecurityAnalyticsService(SecurityEventDao dao) {
        this.dao = dao;
    }

    public Map<String, Long> countByType() {
        return dao.findAll()
                .stream()
                .filter(event -> event.eventType() != null
                        && !event.eventType().isBlank())
                .map(event -> event.eventType()
                        .toUpperCase(Locale.ROOT))
                .collect(Collectors.groupingBy(
                        type -> type,
                        Collectors.counting()
                ));
    }
}