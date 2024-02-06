from collections import defaultdict
import matplotlib.pyplot as plt

# Defining a function called generate_mass_functions and passing the dictionary - evidence_data as a parameter.
def generate_mass_functions(evidence_data):
    # Create mf with float as the default type using defaultdict.
    mf = defaultdict(float)
    
    # Run a loop for each item and beliefs in the evidence_data parameter.
    for item, beliefs in evidence_data.items():
        # Assigning the value for 'malicious' in beliefs dictionary to the frozenset having only 'malicious'.
        mf[frozenset(('malicious',))] = beliefs['malicious']
        
        # Assigning the value for 'benign' in beliefs dictionary to the frozenset having 'benign' and 'unknown'.
        mf[frozenset(('benign', 'unknown'))] = beliefs['benign']
        
    return mf

# Defining a function called combine_mass_functions and passing the list of mass functions as a parameter.
def combine_mass_functions(mass_functions):
    # Get the first mass function in the list and take a copy of it to start the combination process.
    combined_mf = mass_functions[0].copy()
    
    # Run a loop for each subsequent mass function in the list.
    for mf in mass_functions[1:]:
        # Create a new_mf with float as the default type using defaultdict to store the combination results.
        new_mf = defaultdict(float)
        
        # Run a loop for each hypothesis and mass in the combined mass function.
        for h1, m1 in combined_mf.items():
            for h2, m2 in mf.items():
                # Get the intersection of the two hypotheses.
                h = frozenset(set(h1) & set(h2))
                
                # If the intersection is not empty, then combine the masses.
                if h:
                    new_mf[h] += m1 * m2
        
        # Get the total mass for the newly combined mass function.
        total_mass = sum(new_mf.values())

        # Normalizing the masses in the new mass function by dividing them with the total mass as mentioned below.
        for h in new_mf:
            new_mf[h] /= total_mass
        
        # Replace the combined mass function with the newly combined and normalized mass function.
        combined_mf = new_mf

    return combined_mf

# Defining a function called plot_evidence and passing evidence_values dictionary and title as parameters.
def plot_evidence(evidence_values, title):
    # Get the keys (outcomes) and values (probabilities) from the evidence_values dictionary.
    outcomes = list(evidence_values.keys())
    values = [evidence_values[outcome] for outcome in outcomes]
    
    plt.figure(figsize=(10, 6))
    
    # Creating a bar chart with the outcomes and their probabilities. Use blue and red colors.
    plt.bar(outcomes, values, color=['blue', 'red'])
    
    # Set the title of the plot.
    plt.title(title)
    
    # Label the y-axis as 'Probability'.
    plt.ylabel('Probability')
    plt.ylim(0, 1)
    plt.show()

# Defining the main function.
def main():
    # Defining a dictionary called source_ips with IP addresses as keys. Each IP(key) has an associated dictionary indicating beliefs (malicious or benign).
    source_ips = {
        '10.0.2.15': {'malicious': 0.7, 'benign': 0.3}
    }
    
    # Defining a dictionary for destination IPs with similar structure as source_ips.
    destination_ips = {
        '142.250.195.68': {'malicious': 0.6, 'benign': 0.4}
    }
    
    # Defining the source_ports dictionary, which uses port numbers as keys. Each port has a dictionary that indicates whether it is believed to be malicious or benign.
    source_ports = {
        '56696': {'malicious': 0.6, 'benign': 0.4},
        '53': {'malicious': 0.7, 'benign': 0.3},
    }
    
    # Defining a dictionary with the same structure as source_ports for destination ports.
    destination_ports = {
        '1900': {'malicious': 0.6, 'benign': 0.4},
        '61450': {'malicious': 0.6, 'benign': 0.4},
    }

    # Producing a list of integrated evidence dictionaries.
    evidences = [source_ips, destination_ips]
    
    # Use the generate_mass_functions function, which was previously defined, to produce mass functions for each piece of evidence.
    mass_functions = [generate_mass_functions(evidence) for evidence in evidences]
    
    # Utilise the previously defined combine_mass_functions function to combine the generated mass functions.
    combined_mf = combine_mass_functions(mass_functions)

    # Create dictionaries from scratch to store the belief and plausibility measurements.
    belief = defaultdict(float)
    plausibility = defaultdict(float)
    
    # For hypotheses with many elements, tally the mass values to get the uncertainty.
    uncertainty = sum(mass for hypotheses, mass in combined_mf.items() if len(set(hypotheses)) > 1)
    
    # Run a loop for each hypothesis and mass in the combined mass function.
    for hypothesis, mass in combined_mf.items():
        # If the hypothesis contains 'malicious', then update the belief and plausibility measures for 'malicious'.
        if 'malicious' in hypothesis:
            belief['malicious'] += mass
            plausibility['malicious'] += mass

        # If the hypothesis contains 'benign', then update the belief and plausibility measures for 'benign'.
        elif 'benign' in hypothesis:
            belief['benign'] += mass
            plausibility['benign'] += mass
    
    print(f"The belief for 'malicious' is {belief['malicious']}.")
    print(f"The belief for 'benign' is {belief['benign']}.")
    
    print(f"The plausibility for 'malicious' is {plausibility['malicious']}.")
    print(f"The plausibility for 'benign' is {plausibility['benign']}.")

    print(f"The uncertainty is {uncertainty}.")     
    
    # Plotting the belief values using the previously defined plot_evidence function.
    plot_evidence(belief, 'Belief Values')
    
    # Plotting the plausibility values using the previously defined plot_evidence function.
    plot_evidence(plausibility, 'Plausibility Values')
    
# Calling the main function for code execution.
main()
