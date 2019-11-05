#!/usr/bin/env python3
"""
PVDetector v2.0.0
Author: Rocky Slavin
"""
import argparse
import re
import sys
import xml.etree.ElementTree as ET
import owlready2

def detect(ontology_path, mappings_path, fd_out, privacy_policy_path=None):

    try:
        with open(fd_out, 'r') as fd_f:
            dataflows = fd_f.read()
            leaks = get_leaks(dataflows)
            if not leaks:
                sys.exit()
    except IOError as e:
        print(f"Unable to open FlowDroid output file at '{fd_out}': {e}", file=sys.stderr)
        sys.exit(-1)

    try:
        with open(mappings_path, 'r') as map_f:
            mappings = map_f.read()
    except IOError as e:
        print(f"Unable to open mappings file at '{mappings_path}': {e}", file=sys.stderr)
        sys.exit(-1)

    if privacy_policy_path:
        try:
            with open(privacy_policy_path) as pp_f:
                privacy_policy = pp_f.read()
        except IOError as e:
            print(f"Unable to open privacy policy file at '{privacy_policy_path}': {e}", file=sys.stderr)
            sys.exit(-1)
    else:
        privacy_policy = ""

    policy_phrases = get_policy_phrases(privacy_policy, mappings)
    leaks = filter_explicit(leaks, mappings, policy_phrases)
    strong_violations, weak_violations = filter_implicit(leaks, mappings, privacy_policy, ontology_path)

    for wv, phrases in weak_violations.items():
        print(f"[WEAK VIOLATION]: {wv}\n\t[PHRASES]: {phrases}")
    for sv in strong_violations:
        print(f"[STRONG VIOLATION]: {sv}")


def get_leaks(fd_out):
    """
    Parses FlowDroid xml and extracts sources of leaks
    :param fd_out: String representation of FlowDroid xml
    :return: List of sources as method names
    """
    root = ET.fromstring(fd_out)
    sources = [source.get('Statement') for source in root.findall('Results/Result/Sources/Source')]
    return list(map(lambda a: re.sub(r"^.*<(.+)>.*$", r"\1", a), sources))

def get_policy_phrases(policy, mappings):
    """
    Finds all phrases for which there are mappings.
    :param policy: Privacy policy
    :param mappings: API-Phrase mappings
    :return: List of all mapped phrases in policy
    """
    # TODO implement sentiment analysis
    mappings_phrases = set(re.sub(r'^"([^"]+)",.*$', r"\1", mappings, flags=re.M).splitlines())
    return list(filter(lambda a: re.search(r"\b%s\b" % a, policy, re.I), mappings_phrases))


def filter_explicit(leaks, mappings, policy_phrases):
    """
    Returns a set of leaks which are not represented in by the privacy policy phases based on the mappings
    :param leaks: List of leak sources
    :param mappings: API-phrase mappings
    :param policy_phrases: List of all mapped phrases in policy
    :return: Set of leaks which are not directly represented by a mapped phrase in the privacy policy
    """
    if not policy_phrases or not mappings:
        return leaks

    explicit = []
    for leak in leaks:
        leak_phrases = phrases_from_method(leak, mappings)
        # if the intersection of the matched phrases and the privacy policy phrases is empty, keep it
        if not leak_phrases.intersection(set(policy_phrases)):
            explicit.append(leak)

    return explicit


def phrases_from_method(method, mappings):
    """
    Returns all phrases directly mapped to the method
    :param method: Method signature
    :param mappings: API-phrase mappings
    :return: Set of phrases corresponding to the method
    """
    matched_mappings = list(filter(lambda a: method in a, mappings.splitlines()))
    return set(map(lambda a: re.sub(r'^"([^"]+)",.*$', r"\1", a), matched_mappings))


def filter_implicit(leaks, mappings, policy, ontology):
    """

    :param leaks: List of leak sources which are not explicitly mentioned in the policy (use filter_explicit() first)
    :param mappings: API-phrase mappings
    :param policy: String representation of privacy policy
    :param ontology: hierarchical ontology of terms
    :return: Tuple of two lists: List of leaks which are represented thorough higher-level abstractions in the privacy policy,
        List of leaks which are not represented at all in the privacy policy
    """
    weak_violations = {}
    strong_violations = []
    with owlready2.get_ontology(f"file://{ontology}").load() as ontology:
        for leak in leaks:
            leak_phrases = phrases_from_method(leak, mappings)
            for phrase in leak_phrases:
                # TODO make sure synonyms are taken into account
                ancestors = list(ontology[phrase.lower().replace(" ", "_")].ancestors())
                if not ancestors:
                    continue
                # remove prefix
                ancestors = list(map(lambda a: re.sub(r"^.+#(.*)$", r"\1", a.iri), ancestors))
                # remove information and thing nodes
                ancestors = [a for a in ancestors if a.lower() not in ['thing', 'information']]
                # if an ancestor exists in the policy, the leak is a weak violation
                abstract_phrases = list(filter(lambda a: re.search(r"\b%s\b" % a.replace("_", " "), policy, re.I), list(ancestors)))
                if abstract_phrases:
                    weak_violations[leak] = abstract_phrases
                    break
            # if all phrases have been exhausted and no ancestors were found in policy, the leak is a strong violation
            if leak not in weak_violations:
                strong_violations.append(leak)

    return strong_violations, weak_violations


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ontology_path", metavar="<ontology>", help="ontology as .owl file")
    parser.add_argument("mappings_path", metavar="<mappings_path>", help="api-phrase mappings as .csv file")
    parser.add_argument("-p", "--privacy-policy-path", help="privacy policy as text file - blank policy used by default")
    parser.add_argument("fd_out", metavar="<flowdroid_out>", help="dataflow output from FlowDroid as .xml file")
    args = parser.parse_args()

    if args.privacy_policy_path:
        detect(args.ontology_path, args.mappings_path, args.fd_out, args.privacy_policy_path)
    else:
        detect(args.ontology_path, args.mappings_path, args.fd_out)
