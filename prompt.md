Act as an expert cryptographer and academic author preparing a high-tier journal manuscript. I have an updated cryptographic theory for a PUF-based four-phase UAV swarm authentication protocol. 

Your task is to write a flawless, highly polished LaTeX document containing this theory.

**Critical Content Constraints:**
1. **Original Tone:** Present this protocol as a novel, original contribution. You must absolutely completely remove any meta-commentary about this being a "corrected," "revised," or "hardened" version. 
2. **Remove Audit References:** Do not include any tables, sentences, or sections that reference "previous defects," "the audit," or comparisons to a "previous specification."
3. **Confident Academic Voice:** Write with the confident, authoritative tone of a standard IEEE/ACM journal paper. Introduce the stable PUF-derived key, the authenticated ephemeral DH, and the per-pair AEAD credentials simply as the core design features of your proposed protocol.

**Critical Formatting Constraints:**
1. **Spacious Mathematical Typesetting:** The document must look beautiful and easy to read. Avoid congested formulas. Use the `align` environment for multi-step equations and ensure there is generous vertical spacing (`\vspace{...}` or `\\[1ex]`) between distinct mathematical concepts.
2. **Elegant Algorithms:** Use the `algorithm` and `algorithmic` packages to present the four phases cleanly. Ensure steps are well-spaced and easy to follow.
3. **Clean Structure:** Use standard document class (`\documentclass[11pt,a4paper]{article}`) with the `geometry` package for reasonable margins. Include packages like `amsmath`, `amssymb`, `booktabs`, and `xcolor`.

**Source Material:**
Base the cryptographic mathematics, algorithms, and security theorems strictly on the recently generated theoretical model (which included the keyed MACs, exact min-entropy helper-data bounds, and Tamarin symbolic model lemmas).

Output the entire, ready-to-compile LaTeX content within a single code block. Ensure it compiles without errors and results in a visually stunning, spaced-out academic document.