package io.mzaslav.pqc.demo.service;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Service
@RequiredArgsConstructor
@Slf4j
public class RunAllToggleService {

    private static final long DELAY_SECONDS = 5L;

    private final ComparativeBenchmarkService benchmarkService;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "run-all-toggle");
        t.setDaemon(true);
        return t;
    });
    private final AtomicReference<ScheduledFuture<?>> scheduledTask = new AtomicReference<>();
    private final AtomicBoolean cycleInProgress = new AtomicBoolean(false);

    public synchronized boolean toggle(int iterations) {
        ScheduledFuture<?> current = scheduledTask.get();
        if (current != null && !current.isCancelled() && !current.isDone()) {
            current.cancel(false);
            scheduledTask.set(null);
            log.info("Stopped periodic run-all benchmark");
            return false;
        }

        ScheduledFuture<?> task = scheduler.scheduleWithFixedDelay(
                () -> executeCycle(iterations),
                0,
                DELAY_SECONDS,
                TimeUnit.SECONDS
        );
        scheduledTask.set(task);
        log.info("Started periodic run-all benchmark with {} seconds delay between cycles and {} iterations",
                DELAY_SECONDS, iterations);
        return true;
    }

    private void executeCycle(int iterations) {
        if (!cycleInProgress.compareAndSet(false, true)) {
            log.warn("Previous run-all cycle still in progress, skipping this tick");
            return;
        }

        try {
            benchmarkService.runAllBenchmarks(iterations);
        } catch (Exception ex) {
            log.error("Periodic run-all cycle failed", ex);
        } finally {
            cycleInProgress.set(false);
        }
    }

    @PreDestroy
    public void shutdown() {
        ScheduledFuture<?> current = scheduledTask.getAndSet(null);
        if (current != null) {
            current.cancel(false);
        }
        scheduler.shutdownNow();
    }
}
