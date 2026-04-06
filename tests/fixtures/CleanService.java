package com.example;

import java.util.List;
import java.util.ArrayList;

public class CleanService {
    private final List<String> items = new ArrayList<>();

    public void addItem(String item) {
        items.add(item);
    }

    public List<String> getItems() {
        return items;
    }

    public int count() {
        return items.size();
    }
}
