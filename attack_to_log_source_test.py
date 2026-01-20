import argparse
import json
import pandas as pd
import html as html_lib

# ---------------------------------------------------------------------
# SECTION 1: PYTHON DATA PROCESSING
# ---------------------------------------------------------------------
# This section handles the backend logic: reading the raw JSON data,
# filtering it, and preparing it for display in the HTML table.
# ---------------------------------------------------------------------

# Add command line arguments (Optional, for future use)
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--Platform", help = "Use -p or --Platform to supply the platform (Windows, Linux, MacOS)")
args = parser.parse_args()

# Initialize variables
parsed_techniques = {}
parsed_output = []
output_json = "output/attack_tables.json"

# Load the raw data model (The "Source of Truth")
# This JSON contains the mapping between MITRE IDs and Log Events
techniques_model_path = "source/techniques_to_events_mapping.json"
with open(techniques_model_path, "r") as f:
    techniques_model = json.load(f)

# Iterate through every technique in the source file
for technique in techniques_model:
    # Construct a clean dictionary with only the fields we care about
    parsed_techniques = {
        "tactic": technique["tactic"],
        "technique_id": technique["technique_id"],
        "technique_name" : technique["technique"],
        "event_description" : technique["name"],
        "platform": technique["platform"], 
        "table_or_event_id": technique["event_id"], 
        "log_source": technique["log_source"],
        "table_filter": technique["filter_in"]
    }
    parsed_output.append(parsed_techniques)

# Save a simplified JSON file (Optional, useful for debugging)
with open(output_json, "w") as f:
    json.dump(parsed_output, f, indent=2)

# ---------------------------------------------------------------------
# SECTION 2: PANDAS DATAFRAME CLEANING
# ---------------------------------------------------------------------
# We use Pandas to format the data before it becomes HTML.
# This is where we turn lists into strings and generate the Buttons.
# ---------------------------------------------------------------------
df = pd.read_json(output_json)

# 1. Clean up Lists: Convert ["Persistence", "Defense Evasion"] -> "Persistence, Defense Evasion"
df["tactic"] = df["tactic"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
df["platform"] = df["platform"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)

# 2. Format the Filter Column: Convert complex dictionary objects into readable strings
def format_filter_data(cell_data):
    if not cell_data: return ""
    if isinstance(cell_data, list):
        items = []
        for entry in cell_data:
            if isinstance(entry, dict):
                # Turn {"Key": "Value"} into "Key: Value"
                dict_str = ", ".join([f"{key}: {value}" for key, value in entry.items()])
                items.append(dict_str)
            else:
                items.append(str(entry))
        return "; ".join(items)
    return str(cell_data)

df["table_filter"] = df["table_filter"].apply(format_filter_data)

# 3. Create the "Copy KQL" Button Column
# This function generates the HTML <button> code for every row.
def create_copy_button(row):
    t_name = str(row['table_or_event_id']) 
    raw_filter = row['table_filter']
    
    # Logic: If there is no filter, create a disabled "Grey" button
    if not raw_filter or raw_filter.lower() == 'nan' or raw_filter.strip() == "":
        return ('<button class="copy-btn disabled-btn" disabled>'
                '<i class="fa-solid fa-ban"></i> No Filter</button>')
    
    # Logic: If there IS a filter, create an active "Green" button
    # We escape quotes to ensure the JavaScript function doesn't break
    safe_name = t_name.replace("'", "\\'")
    safe_filter = str(raw_filter).replace("'", "\\'")
    
    return (f'<button class="copy-btn active-btn" onclick="generateKQL(this, \'{safe_name}\', \'{safe_filter}\')">'
            f'<i class="fa-solid fa-terminal"></i> Copy KQL</button>')

df['Query'] = df.apply(create_copy_button, axis=1)

# 4. Sanitize & Add Tooltips
# Security: We escape HTML characters (<, >) to prevent XSS attacks in the text.
# UX: We wrap the text in a <span> with a 'title' attribute so hovering shows the full text.
for col in df.columns:
    if col != 'Query':
        def add_tooltip(x):
            if not x: return ""
            safe_text = html_lib.escape(str(x))
            return f'<span title="{safe_text}">{safe_text}</span>'
        df[col] = df[col].apply(add_tooltip)

# 5. Generate the HTML Table structure
html = df.to_html(
    classes="display stripe hover cell-border order-column", 
    table_id="jsonTable", 
    index=False,
    escape=False # Important: We set this to False so our <button> tags render as buttons, not text.
)

# ---------------------------------------------------------------------
# SECTION 3: WRITING THE HTML FILE
# ---------------------------------------------------------------------
with open("table.html", "w") as f:
    f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Signal Trace</title>
            
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            
    <style>
    /* --------------------------------------------------- */
    /* CSS STYLING SECTION                                 */
    /* --------------------------------------------------- */

    /* 1. Global Page Styles */
    body {{
        margin: 0;
        padding: 0;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f4f6f9; /* Light Grey Background */
        color: #333;
    }}

    /* 2. Main Content Card */
    .content-wrapper {{
        width: 98%; /* Takes up almost full screen width */
        margin: 20px auto;
        background-color: #ffffff;
        padding: 20px;
        border-radius: 8px; /* Rounded corners */
        box-shadow: 0 4px 12px rgba(0,0,0,0.1); /* Subtle drop shadow */
        box-sizing: border-box;
    }}

    /* 3. Header Styling */
    .header-container {{
        text-align: center;
        margin-bottom: 20px;
        border-bottom: 2px solid #ecf0f1;
        padding-bottom: 20px;
    }}
    .header-icon {{
        font-size: 3rem;
        color: #e74c3c; /* Red Shield Icon */
        margin-bottom: 10px;
    }}
    h1 {{
        color: #2c3e50; /* Dark Blue Title */
        font-size: 1.8rem;
        margin: 0;
    }}
    .subtitle {{
        color: #7f8c8d; /* Grey Subtitle */
        font-size: 0.9rem;
        margin-top: 5px;
    }}

    /* 4. Table Styling */
    table.dataTable {{
        width: 100% !important;
    }}
    /* Dark Blue Header Row */
    table.dataTable thead th {{
        background-color: #2c3e50;
        color: white;
        font-weight: 600;
        padding: 12px;
        white-space: nowrap; 
    }}
    
    /* Cell Behavior */
    td {{
        vertical-align: middle !important;
        white-space: nowrap; /* Forces short text to stay on one line */
        overflow: hidden;
        text-overflow: ellipsis; /* Adds '...' if text is too long */
        max-width: 400px;
        cursor: default;
    }}

    /* Exception: Allow description and filters to wrap because they are long */
    td:nth-child(4), td:nth-child(8) {{
        white-space: normal;
        word-wrap: break-word;
        min-width: 300px;
        max-width: 600px;
    }}

    /* 5. Button Styling */
    .copy-btn {{
        min-width: 110px;
        justify-content: center;
        padding: 6px 10px;
        border-radius: 4px;
        font-family: 'Consolas', 'Monaco', monospace; /* Code font */
        font-size: 0.8em;
        white-space: nowrap;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.2s ease;
    }}

    /* Active (Green) State */
    .active-btn {{
        background-color: #2d3436;
        color: #00b894;
        border: 1px solid #00b894;
        cursor: pointer;
    }}
    .active-btn:hover {{
        background-color: #00b894;
        color: #2d3436;
    }}
    /* "Copied" State (Blue) */
    .active-btn.copied {{
        background-color: #0984e3;
        color: white;
        border-color: #0984e3;
    }}
    /* Disabled (Grey) State */
    .disabled-btn {{
        background-color: #dfe6e9;
        color: #b2bec3;
        border: 1px solid #d6d6d6;
        cursor: not-allowed;
        opacity: 0.7;
    }}
    
    /* 6. Footer Dropdowns */
    tfoot select {{
        width: 100%;
        padding: 6px;
        border: 1px solid #dfe6e9;
        border-radius: 4px;
        background-color: #fdfdfd;
        box-sizing: border-box; 
    }}

    /* 7. Author Credit (Terminal Style) */
    .console-credit {{
        text-align: center;
        margin-top: 40px;
        font-family: 'Consolas', 'Monaco', monospace;
        background-color: #2d3436;
        color: #dfe6e9;
        padding: 12px 20px;
        border-radius: 6px;
        font-size: 0.9em;
        display: table; 
        margin-left: auto;
        margin-right: auto;
        box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    }}
    .prompt {{ color: #00b894; margin-right: 10px; }}
    .user-link {{
        color: #e74c3c;
        font-weight: bold;
        text-decoration: none;
        border-bottom: 1px dashed #e74c3c;
        transition: all 0.3s;
    }}
    .user-link:hover {{
        color: #ffffff;
        border-bottom-style: solid;
        border-bottom-color: #ffffff;
        text-shadow: 0 0 8px rgba(255, 255, 255, 0.5);
    }}

    /* 8. Legal Footer */
    .legal-footer {{
        margin-top: 20px;
        text-align: center;
        font-size: 0.75rem;
        color: #95a5a6;
        border-top: 1px solid #eee;
        padding-top: 15px;
    }}
    </style>
            
</head>
<body>

<div class="content-wrapper">
    <div class="header-container">
        <div class="header-icon"><i class="fa-solid fa-shield-halved"></i></div>
        <h1>Signal Trace</h1>
        <div class="subtitle">Tactical Log Mapper for MITRE ATT&CK®</div>
    </div>

    {html}

    <div class="console-credit">
        <span class="prompt">root@soc:~$</span> echo "Created by <a href="https://www.linkedin.com/in/anthonyndutra/" target="_blank" class="user-link">Anthony Dutra</a>"
    </div>

    <div class="legal-footer">
        <p>© 2024 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.</p>
        <p>Comparison data provided by the OSSEM Project.</p>
    </div>
</div>

<script>
// ---------------------------------------------------
// JAVASCRIPT LOGIC SECTION
// ---------------------------------------------------

/**
 * FUNCTION 1: KQL GENERATOR
 * Takes the table name and the filter string (e.g. "ActionType: Created")
 * and combines them into a valid Kusto Query Language string.
 */
function generateKQL(btnElement, tableName, filterString) {{
    let query = tableName; // Start with table name (e.g., DeviceProcessEvents)

    // Parse the filter string if it exists
    if (filterString && filterString.trim() !== "") {{
        let conditions = [];
        // Check if filter is valid (not "None" or "nan")
        if (filterString !== "None" && filterString !== "nan") {{
            let filters = filterString.split(';'); // Split multiple filters
            filters.forEach(function(f) {{
                let parts = f.split(':');
                if (parts.length >= 2) {{
                    let key = parts[0].trim();
                    let value = parts.slice(1).join(':').trim();
                    // Create KQL syntax: Column == 'Value'
                    conditions.push(key + " == '" + value + "'");
                }}
            }});
        }}
        
        // Append filters to query using " | where "
        if (conditions.length > 0) {{
            query += " | where " + conditions.join(" and ");
        }}
    }}

    // Copy to Clipboard API
    navigator.clipboard.writeText(query).then(function() {{
        // UI Feedback: Change button to "Copied!" temporarily
        let originalHTML = btnElement.innerHTML;
        btnElement.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        btnElement.classList.add('copied');
        setTimeout(function() {{
            btnElement.innerHTML = originalHTML;
            btnElement.classList.remove('copied');
        }}, 2000);
    }}, function(err) {{
        console.error('Copy failed: ', err);
    }});
}}

/**
 * FUNCTION 2: DYNAMIC DROPDOWNS
 * This function updates the filter menus at the bottom of the table.
 * It ensures that if you filter by "Windows", the other dropdowns only show
 * options relevant to Windows.
 */
function updateDropdowns(api) {{
    api.columns().every(function () {{
        var column = this;
        var footer = $(column.footer());
        var select = footer.find('select');
        
        // Skip updating if this specific filter is active 
        // (Prevents the "Trapped" issue where you can't switch options)
        if (select.val() && select.val() !== "") {{
            return;
        }}

        // Get unique values from the CURRENTLY visible rows
        var uniqueValues = new Set();
        
        // Extract data from the filtered rows API
        var filteredData = api.column(column.index(), {{ search: 'applied' }}).data();
        
        filteredData.each(function(d) {{
            if (!d) return;
            if (d.includes('<button')) return; // Skip buttons column

            // Decode HTML entities (because we wrapped text in spans)
            var tempDiv = document.createElement("div");
            tempDiv.innerHTML = d;
            var decoded = tempDiv.textContent || tempDiv.innerText || "";

            // Handle comma-separated lists (e.g. Windows, Linux)
            decoded.split(',').forEach(function (item) {{
                let cleanItem = item.trim();
                if (cleanItem) uniqueValues.add(cleanItem);
            }});
        }});

        // Rebuild the dropdown with new valid options
        var currentVal = select.val();
        select.empty();
        select.append('<option value="">All</option>');

        Array.from(uniqueValues).sort().forEach(function (val) {{
            select.append('<option value="' + val + '">' + val + '</option>');
        }});
        
        // Restore selection (if it still exists in the new set)
        if (currentVal) {{
            select.val(currentVal);
        }}
    }});
}}

// ---------------------------------------------------
// MAIN INITIALIZATION
// ---------------------------------------------------
$(document).ready(function () {{
    var tableElement = $('#jsonTable');
    
    // 1. Manually create the TFOOT structure by cloning the THEAD
    // We do this because DataTables doesn't create input footers by default
    var tfoot = $('<tfoot></tfoot>');
    var headerRow = tableElement.find('thead tr').clone();
    headerRow.find('th').empty(); // Clear text so we can put dropdowns in later
    tfoot.append(headerRow);
    tableElement.append(tfoot);

    // 2. Initialize the DataTable
    var table = tableElement.DataTable({{
        paging: true,
        searching: true,
        ordering: true,
        pageLength: 25,
        autoWidth: false,
        scrollX: true, // Enable horizontal scroll for small screens
        order: [],
        initComplete: function () {{
            // 3. Create the Select Elements (Initially Empty)
            this.api().columns().every(function () {{
                var column = this;
                var headerText = $(column.header()).text().trim();
                if (headerText === "Query") return; // Skip Query Column

                var footerCell = $(column.footer());
                footerCell.empty(); 
                
                // Create Dropdown with Regex Search Logic
                var select = $('<select><option value="">All</option></select>')
                    .appendTo(footerCell)
                    .on('change', function () {{
                        const rawInput = $(this).val();
                        const escapedTerm = $.fn.dataTable.util.escapeRegex(rawInput);
                        // Regex ensures that filtering "Windows" doesn't accidentally match "Windows Server"
                        if (rawInput === "") {{
                            column.search("").draw();
                        }} else {{
                            column.search('(^|,)\\\\s*' + escapedTerm + '\\\\s*(,|$)', true, false).draw();
                        }}
                    }});
            }});

            // 4. Trigger initial population of dropdowns
            updateDropdowns(this.api());
        }}
    }});

    // 5. Event Listener: Whenever the table redraws (sort/filter), update the dropdowns
    table.on('draw', function () {{
        updateDropdowns(table);
    }});
}});
</script>
</body>
</html>
""")