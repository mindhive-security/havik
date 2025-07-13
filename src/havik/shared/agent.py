from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableSequence
from os import getenv

LLM_HOST = getenv('LLM_HOST')


llm = OllamaLLM(
    model="mistral",
    base_url=f"http://{LLM_HOST}",
)


def explain_bucket_risk(bucket_config: dict, score: int):
    bucket_name = bucket_config["BucketName"]
    encryption = bucket_config["Encryption"]
    public = bucket_config["PublicAccess"]["Status"]
    policy_status = bucket_config["PolicyEval"]["Status"]
    policy_reason = bucket_config["PolicyEval"]["Reason"]
    creation_date = bucket_config["CreationDate"]
    location = bucket_config["Location"]

    extra_context = """
DORA (Digital Operational Resilience Act) is an EU regulation that requires financial institutions to implement secure ICT risk management practices, including data encryption, secure access policies, and clear accountability for third-party service providers.
"""

    prompt = PromptTemplate.from_template(f"""
You are a cloud security expert.

A bucket named "{bucket_name}" has a calculated risk score of {score} out of 100.

Here is the configuration:
- Encryption algorithm: {encryption.get('Algorithm')}
- Encryption key: {encryption.get('Key')}
- Encryption key location: {encryption.get('KeyLocation')}
- Encryption in transit TLS: {encryption.get('TLS')}
- Encryption customer-side is possible SSE-C: {encryption.get('SSE-C')}
- Public Access: {public}
- IAM Policy Evaluation: {policy_status} — {policy_reason}
- Location: {location}
- Creation Date: {creation_date}

Treat empty values as not provided.

Please:
1. Explain **why** this bucket got this risk score.
2. Identify **potential issues**, even if risk = 0.
3. Give **recommendations** to improve security even further.
4. Define if the configuration compliant to DORA, GDPR, CIS, NIST 800-53 and ISO 27018/27001

Rules:
SSE-C is bad an should not be used.
TLS must be enforced.
Resource and key must reside in Europe.
Algorithm should be secure, e.g. AES-256
Public access must be blocked.
Creation date affects risk - short lived resources are less risky.

Write clearly and briefly in bullet points.

Return plain text, no JSON. Do not modify the score value,
but provide possible corrections to the value if required.

{extra_context}
""")

    chain = RunnableSequence(prompt | llm | StrOutputParser())

    response = chain.invoke({})

    return response
