package io.opentdf.platform.sdk;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class AssertionRegistry {
    private final List<AssertionBinder> binders;
    private final Map<String, AssertionValidator> validators;

    public AssertionRegistry() {
        this.binders = new CopyOnWriteArrayList<>();
        this.validators = new ConcurrentHashMap<>();
    }

    public void registerBinder(AssertionBinder binder) {
        binders.add(binder);
    }

    public void registerValidator(AssertionValidator validator) {
        String schema = validator.getSchema();
        validators.put(schema, validator);
    }

    public List<AssertionBinder> getBinders() {
        return Collections.unmodifiableList(binders);
    }

    public void setBinders(List<AssertionBinder> binders) {
        this.binders.clear();
        this.binders.addAll(binders);
    }

    public Map<String, AssertionValidator> getValidators() {
        return Collections.unmodifiableMap(validators);
    }

    public void setValidators(Map<String, AssertionValidator> validators) {
        this.validators.clear();
        this.validators.putAll(validators);
    }
}
