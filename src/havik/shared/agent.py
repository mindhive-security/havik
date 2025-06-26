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
    #encryption = bucket_config["Encryption"]
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
- Public Access: {public}
- IAM Policy Evaluation: {policy_status} — {policy_reason}
- Location: {location}
- Creation Date: {creation_date}

Please:
1. Explain **why** this bucket got this risk score.
2. Identify **potential issues**, even if risk = 0.
3. Give **recommendations** to improve security even further.
4. Define if the configuration compliant to DORA, CIS and ISO 27018/27001

Write clearly and briefly in bullet points.

{extra_context}

Please write your full output in clean, semantic HTML. Use bullet points, headings, and paragraphs as needed.
Do not include any Markdown or plain text — only HTML.
""")

    chain = RunnableSequence(prompt | llm | StrOutputParser())

    response = chain.invoke({})
    
    return response
