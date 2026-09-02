import pytest

from retrieval.router import classify_query


@pytest.mark.parametrize("question", [
    "Why did this user access the file?",
    "Which host is linked to this account?",
    "Show the path from the user to the technique.",
    "What devices are connected to this user?",
    "Why is the account connected to an external host?",
])
def test_structural_questions(question):
    assert classify_query(question) == "structural"


@pytest.mark.parametrize("question", [
    "What is this user's department?",
    "When did the user log on?",
    "List the user's known hosts.",
    "Tell me the confidence of this relation.",
    "What technique was observed?",
])
def test_lookup_questions(question):
    assert classify_query(question) == "lookup"


def test_empty_question_is_rejected():
    with pytest.raises(ValueError):
        classify_query(" ")
