use comfy_table::{Table, Cell, presets::UTF8_FULL};

fn table() {
    // Create a new table
    let mut table = Table::new();

    // Set a preset style (optional)
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
        .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS);

    // Add header
    table.set_header(vec!["ID", "Name", "Age", "City"]);

    // Add rows
    table.add_row(vec!["1", "Alice", "30", "New York"]);
    table.add_row(vec!["2", "Bob", "25", "San Francisco"]);
    table.add_row(vec!["3", "Charlie", "35", "Chicago"]);
    table.add_row(vec![
        Cell::new("4").add_attribute(comfy_table::Attribute::Bold),
        "Diana".into(),
        "28".into(),
        "Seattle".into(),
    ]);

    // Print the table
    println!("{}", table);
}