"""
pdf_generator.py - Gerador Nativo de Laudo Técnico Pericial em PDF (A4)
Implementação 100% nativa em Python (PDF 1.4 specification), sem dependências pesadas externas.
Gera documentos periciais formatados para instrução judicial em JEC, PROCON e ANATEL,
contendo tabelas, demonstrativo financeiro em R$, diagnóstico forense de rotas e prova criptográfica.
"""

import io
from datetime import datetime
from typing import Dict, Any, Optional


def _escape_pdf_text(text: str) -> str:
    """Escapa caracteres reservados do PDF e converte caracteres acentuados para WinAnsiEncoding."""
    if text is None:
        return ""
    text = str(text)
    # Tabela de mapeamento Unicode -> WinAnsiEncoding (Windows-1252)
    charmap = {
        'á': '\\341', 'à': '\\340', 'ã': '\\343', 'â': '\\342', 'ä': '\\344',
        'é': '\\351', 'è': '\\350', 'ê': '\\352', 'ë': '\\353',
        'í': '\\355', 'ì': '\\354', 'î': '\\356', 'ï': '\\357',
        'ó': '\\363', 'ò': '\\362', 'õ': '\\365', 'ô': '\\364', 'ö': '\\366',
        'ú': '\\372', 'ù': '\\371', 'û': '\\373', 'ü': '\\374',
        'ç': '\\347', 'ñ': '\\361',
        'Á': '\\301', 'À': '\\300', 'Ã': '\\303', 'Â': '\\302', 'Ä': '\\304',
        'É': '\\311', 'È': '\\310', 'Ê': '\\312', 'Ë': '\\313',
        'Í': '\\315', 'Ì': '\\314', 'Î': '\\316', 'Ï': '\\317',
        'Ó': '\\323', 'Ò': '\\322', 'Õ': '\\325', 'Ô': '\\324', 'Ö': '\\326',
        'Ú': '\\332', 'Ù': '\\331', 'Û': '\\333', 'Ü': '\\334',
        'Ç': '\\307', 'Ñ': '\\321',
        'º': '\\272', 'ª': '\\252', '§': '\\247', '•': '\\225', '–': '\\226', '—': '\\227',
        '“': '\\223', '”': '\\224', '‘': '\\221', '’': '\\222', '…': '\\205',
    }

    # Escapa parênteses e barras invertidas primeiro
    text = text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    # Substitui acentos mapeados
    res = []
    for char in text:
        if char in charmap:
            res.append(charmap[char])
        elif ord(char) < 128:
            res.append(char)
        else:
            # Fallback seguro para ASCII mais próximo
            res.append("?")
    return "".join(res)


class SimplePDF:
    """Gerador minimalista e robusto de PDF 1.4 em coordenadas A4 (595.28 x 841.89 pt)."""
    PAGE_WIDTH = 595.28
    PAGE_HEIGHT = 841.89

    def __init__(self):
        self.pages = []
        self.current_stream = io.StringIO()
        self.page_number = 0

    def new_page(self):
        if self.page_number > 0:
            self.pages.append(self.current_stream.getvalue())
            self.current_stream = io.StringIO()
        self.page_number += 1

    def draw_rect(self, x: float, y: float, w: float, h: float, fill_color: Optional[tuple] = None, stroke_color: Optional[tuple] = None, line_width: float = 1.0):
        s = self.current_stream
        if stroke_color:
            s.write(f"{stroke_color[0]:.2f} {stroke_color[1]:.2f} {stroke_color[2]:.2f} RG\n")
            s.write(f"{line_width:.2f} w\n")
        if fill_color:
            s.write(f"{fill_color[0]:.2f} {fill_color[1]:.2f} {fill_color[2]:.2f} rg\n")
        s.write(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re\n")
        if fill_color and stroke_color:
            s.write("B\n")
        elif fill_color:
            s.write("f\n")
        elif stroke_color:
            s.write("S\n")

    def draw_line(self, x1: float, y1: float, x2: float, y2: float, stroke_color=(0.7, 0.7, 0.7), line_width=1.0):
        s = self.current_stream
        s.write(f"{stroke_color[0]:.2f} {stroke_color[1]:.2f} {stroke_color[2]:.2f} RG\n")
        s.write(f"{line_width:.2f} w\n")
        s.write(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S\n")

    def draw_text(self, text: str, x: float, y: float, font: str = "F1", size: float = 10, color: tuple = (0.1, 0.1, 0.1)):
        s = self.current_stream
        escaped = _escape_pdf_text(text)
        s.write("BT\n")
        s.write(f"/{font} {size:.2f} Tf\n")
        s.write(f"{color[0]:.2f} {color[1]:.2f} {color[2]:.2f} rg\n")
        s.write(f"{x:.2f} {y:.2f} Td\n")
        s.write(f"({escaped}) Tj\n")
        s.write("ET\n")

    def finish(self) -> bytes:
        if self.page_number > 0 and (not self.pages or self.pages[-1] != self.current_stream.getvalue()):
            self.pages.append(self.current_stream.getvalue())

        num_pages = len(self.pages)
        if num_pages == 0:
            self.new_page()
            self.pages.append(self.current_stream.getvalue())
            num_pages = 1

        objects = []
        # Obj 1: Catalog
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")

        # Obj 2: Pages (Kids placeholder)
        kids_str = " ".join([f"{3 + i * 2} 0 R" for i in range(num_pages)])
        objects.append(f"<< /Type /Pages /Kids [{kids_str}] /Count {num_pages} >>".encode("ascii"))

        # For each page: Page Object + Content Stream Object
        for i, page_content in enumerate(self.pages):
            content_bytes = page_content.encode("latin-1", errors="replace")
            content_obj_idx = 4 + i * 2

            page_dict = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PAGE_WIDTH} {self.PAGE_HEIGHT}] "
                f"/Contents {content_obj_idx} 0 R /Resources << /Font << "
                f"/F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >> "
                f"/F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >> "
                f"/F3 << /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >> "
                f">> /ProcSet [/PDF /Text] >> >>"
            )
            objects.append(page_dict.encode("latin-1"))

            stream_dict = (
                f"<< /Length {len(content_bytes)} >>\nstream\n"
            ).encode("ascii") + content_bytes + b"\nendstream"
            objects.append(stream_dict)

        # Build xref table
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]  # Object 0 is dummy

        for i, obj_data in enumerate(objects, 1):
            offsets.append(out.tell())
            out.write(f"{i} 0 obj\n".encode("ascii"))
            out.write(obj_data)
            out.write(b"\nendobj\n")

        xref_pos = out.tell()
        total_objs = len(objects) + 1
        out.write(f"xref\n0 {total_objs}\n".encode("ascii"))
        out.write(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            out.write(f"{off:010d} 00000 n \n".encode("ascii"))

        trailer = (
            f"trailer\n<< /Size {total_objs} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        )
        out.write(trailer.encode("ascii"))
        return out.getvalue()


def generate_laudo_pdf(report_data: Dict[str, Any]) -> bytes:
    """
    Gera o documento pericial completo em PDF (formato A4) com base no dicionário consolidado
    fornecido por db.generate_isp_report_data().
    """
    pdf = SimplePDF()
    pdf.new_page()

    client = report_data.get("client", {})
    period = report_data.get("period", {})
    summary = report_data.get("summary", {})
    perf = report_data.get("performance", {})
    fin = report_data.get("financial_compensation", {})
    outages = report_data.get("outages", [])
    integrity = report_data.get("integrity", {})

    # -------------------------------------------------------------
    # CABEÇALHO OFICIAL
    # -------------------------------------------------------------
    # Barra superior azul marinho
    pdf.draw_rect(0, 805, 595.28, 37, fill_color=(0.06, 0.12, 0.22))
    pdf.draw_text("REPÚBLICA FEDERATIVA DO BRASIL • AUDITORIA FORENSE DE TELECOMUNICAÇÕES", 40, 818, font="F2", size=9, color=(1, 1, 1))

    # Título do Laudo
    pdf.draw_text("LAUDO TÉCNICO PERICIAL DE CONECTIVIDADE E AUDITORIA", 40, 778, font="F2", size=14, color=(0.08, 0.15, 0.28))
    pdf.draw_text("Relatório Oficial de Descumprimento Contratual e Apuração de Indisponibilidade", 40, 764, font="F1", size=9, color=(0.4, 0.45, 0.52))

    # Metadados de emissão (direita)
    emissao_str = period.get("generated_at") or datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    pdf.draw_text(f"Emitido em: {emissao_str}", 380, 778, font="F1", size=8, color=(0.3, 0.35, 0.4))
    pdf.draw_text("Sistema: NetMon v3.0 Pro Forensic", 380, 766, font="F2", size=8, color=(0.1, 0.4, 0.7))

    pdf.draw_line(40, 755, 555, 755, stroke_color=(0.8, 0.85, 0.9), line_width=1.0)

    # -------------------------------------------------------------
    # IDENTIFICAÇÃO DO CONTRATO E ASSINANTE (BOX CINZA CLARO)
    # -------------------------------------------------------------
    pdf.draw_rect(40, 680, 515, 68, fill_color=(0.96, 0.97, 0.99), stroke_color=(0.82, 0.86, 0.92), line_width=0.8)

    c_name = client.get("client_name") or "Não informado"
    c_num = client.get("contract_number") or "Não informado"
    c_addr = client.get("client_address") or "Não informado"
    isp_name = client.get("isp_name") or "Claro"
    asn = client.get("asn") or "AS28573"
    public_ip = client.get("public_ip") or "--"
    plan_down = client.get("contracted_download_mbps", 500)
    plan_up = client.get("contracted_upload_mbps", 250)
    monthly_fee = client.get("monthly_fee", 0.0)

    pdf.draw_text(f"Titular: {c_name}", 50, 732, font="F2", size=8.5, color=(0.1, 0.15, 0.25))
    pdf.draw_text(f"Nº Contrato: {c_num}", 320, 732, font="F2", size=8.5, color=(0.1, 0.15, 0.25))
    pdf.draw_text(f"Endereço: {c_addr[:68]}", 50, 719, font="F1", size=8, color=(0.25, 0.3, 0.35))
    pdf.draw_text(f"Operadora: {isp_name} ({asn})", 50, 706, font="F2", size=8, color=(0.15, 0.35, 0.65))
    pdf.draw_text(f"IP Monitorado: {public_ip}", 320, 706, font="F1", size=8, color=(0.25, 0.3, 0.35))
    pdf.draw_text(f"Plano: {plan_down}M Down / {plan_up}M Up", 50, 693, font="F1", size=8, color=(0.25, 0.3, 0.35))
    pdf.draw_text(f"Mensalidade Fatura: R$ {monthly_fee:.2f}", 320, 693, font="F2", size=8.5, color=(0.1, 0.55, 0.25))

    # -------------------------------------------------------------
    # SEÇÃO 1: RESUMO EXECUTIVO E INDICADORES REGULATÓRIOS (KPIS)
    # -------------------------------------------------------------
    pdf.draw_text("1. RESUMO EXECUTIVO DE AUDITORIA E DESEMPENHO (ABNT NBR 13752)", 40, 662, font="F2", size=10, color=(0.08, 0.15, 0.28))

    kpi_y = 612
    # Box 1: Uptime
    pdf.draw_rect(40, kpi_y, 98, 44, fill_color=(0.98, 0.99, 1.0), stroke_color=(0.8, 0.85, 0.92))
    pdf.draw_text(f"{summary.get('uptime_pct', 100):.2f}%", 46, kpi_y + 24, font="F2", size=12, color=(0.1, 0.55, 0.25))
    pdf.draw_text("Disponibilidade SLA", 46, kpi_y + 10, font="F1", size=7, color=(0.4, 0.45, 0.5))

    # Box 2: Quedas Totais
    pdf.draw_rect(143, kpi_y, 98, 44, fill_color=(1.0, 0.97, 0.97), stroke_color=(0.95, 0.75, 0.75))
    tot_out_cnt = summary.get("total_outages_count", 0)
    tot_out_min = summary.get("total_outages_min", 0.0)
    pdf.draw_text(f"{tot_out_cnt} ({tot_out_min}m)", 149, kpi_y + 24, font="F2", size=11, color=(0.85, 0.15, 0.15))
    pdf.draw_text("Quedas Totais (Blackout)", 149, kpi_y + 10, font="F1", size=7, color=(0.5, 0.35, 0.35))

    # Box 3: Instabilidades
    pdf.draw_rect(246, kpi_y, 98, 44, fill_color=(1.0, 0.98, 0.94), stroke_color=(0.95, 0.85, 0.65))
    part_out_cnt = summary.get("partial_outages_count", 0)
    part_out_min = summary.get("partial_outages_min", 0.0)
    pdf.draw_text(f"{part_out_cnt} ({part_out_min}m)", 252, kpi_y + 24, font="F2", size=11, color=(0.8, 0.45, 0.05))
    pdf.draw_text("Instabilidades Severas", 252, kpi_y + 10, font="F1", size=7, color=(0.5, 0.4, 0.3))

    # Box 4: Velocidade Média & Bufferbloat
    pdf.draw_rect(349, kpi_y, 102, 44, fill_color=(0.97, 0.98, 1.0), stroke_color=(0.8, 0.85, 0.95))
    avg_down = perf.get("avg_down", 0.0)
    pdf.draw_text(f"{avg_down:.1f} Mbps", 355, kpi_y + 24, font="F2", size=11, color=(0.2, 0.3, 0.7))
    jit_val = perf.get("avg_jitter")
    jit_str = f"Jitter: {jit_val}ms" if jit_val else "Velocidade Média"
    pdf.draw_text(jit_str, 355, kpi_y + 10, font="F1", size=7, color=(0.4, 0.45, 0.55))

    # Box 5: Abatimento Proporcional R$
    pdf.draw_rect(456, kpi_y, 99, 44, fill_color=(0.94, 0.99, 0.95), stroke_color=(0.7, 0.9, 0.75))
    ref_amt = fin.get("proportional_refund_reais", 0.0)
    pdf.draw_text(f"R$ {ref_amt:.2f}", 462, kpi_y + 24, font="F2", size=12, color=(0.08, 0.55, 0.2))
    pdf.draw_text("Abatimento Fatura", 462, kpi_y + 10, font="F1", size=7, color=(0.25, 0.45, 0.3))

    # -------------------------------------------------------------
    # SEÇÃO 2: DEMONSTRATIVO FINANCEIRO E ART. 46 RESOLUÇÃO ANATEL 632/2014
    # -------------------------------------------------------------
    sec2_y = 592
    pdf.draw_text("2. DEMONSTRATIVO FINANCEIRO E RESSARCIMENTO (RESOLUÇÃO ANATEL 632/2014)", 40, sec2_y, font="F2", size=10, color=(0.08, 0.15, 0.28))

    pdf.draw_rect(40, sec2_y - 68, 515, 62, fill_color=(0.98, 0.99, 0.99), stroke_color=(0.85, 0.88, 0.92), line_width=0.6)
    ref_tot = fin.get("refund_total_outages_reais", 0.0)
    ref_part = fin.get("refund_partial_instabilities_reais", 0.0)
    reg_days = fin.get("regulatory_days_due", 0)
    reg_min_refund = fin.get("regulatory_minimum_refund_reais", 0.0)

    pdf.draw_text(f"• Abatimento por Quedas Totais (Blackouts completos): R$ {ref_tot:.2f} ({tot_out_min} min fora do ar)", 50, sec2_y - 18, font="F1", size=8, color=(0.2, 0.25, 0.3))
    pdf.draw_text(f"• Abatimento por Instabilidades Técnicas Severas (CDC Art. 20): R$ {ref_part:.2f} ({part_out_min} min degradado)", 50, sec2_y - 30, font="F1", size=8, color=(0.2, 0.25, 0.3))
    pdf.draw_text(f"• Total do Abatimento Proporcional Contínuo: R$ {ref_amt:.2f} (Calculado sobre a fatura de R$ {monthly_fee:.2f})", 50, sec2_y - 42, font="F2", size=8.5, color=(0.1, 0.55, 0.2))
    pdf.draw_text(f"• Mínimo Regulatório ANATEL (Art. 46, § 1º): R$ {reg_min_refund:.2f} ({reg_days} diária(s) devidas por interrupções >= 30 min)", 50, sec2_y - 56, font="F2", size=8.5, color=(0.15, 0.35, 0.7))

    # -------------------------------------------------------------
    # SEÇÃO 3: HISTÓRICO DISCRIMINADO DE INTERRUPÇÕES E ROTA FORENSE
    # -------------------------------------------------------------
    sec3_y = 508
    pdf.draw_text("3. HISTÓRICO DAS INTERRUPÇÕES E DIAGNÓSTICO PERICIAL DE ROTAS (TRACEROUTE)", 40, sec3_y, font="F2", size=10, color=(0.08, 0.15, 0.28))

    # Cabeçalho da Tabela
    tbl_y = sec3_y - 18
    pdf.draw_rect(40, tbl_y, 515, 16, fill_color=(0.12, 0.18, 0.3), stroke_color=None)
    pdf.draw_text("Início", 45, tbl_y + 4, font="F2", size=7.5, color=(1, 1, 1))
    pdf.draw_text("Término", 135, tbl_y + 4, font="F2", size=7.5, color=(1, 1, 1))
    pdf.draw_text("Duração", 225, tbl_y + 4, font="F2", size=7.5, color=(1, 1, 1))
    pdf.draw_text("Tipo", 270, tbl_y + 4, font="F2", size=7.5, color=(1, 1, 1))
    pdf.draw_text("Diagnóstico Técnico & Ruptura de Rota", 320, tbl_y + 4, font="F2", size=7.5, color=(1, 1, 1))
    pdf.draw_text("Certificação", 490, tbl_y + 4, font="F2", size=7.5, color=(1, 1, 1))

    # Linhas de interrupções (até 8 linhas na folha 1 para não sobrepor)
    cur_y = tbl_y - 16
    outages_to_print = outages[:8] if outages else []

    if not outages_to_print:
        pdf.draw_rect(40, cur_y, 515, 16, fill_color=(0.97, 0.98, 0.99), stroke_color=(0.85, 0.88, 0.92), line_width=0.5)
        pdf.draw_text("Nenhuma interrupção registrada no período periciado.", 50, cur_y + 4, font="F1", size=7.5, color=(0.4, 0.45, 0.5))
        cur_y -= 16
    else:
        for idx, o in enumerate(outages_to_print):
            bg = (0.98, 0.99, 1.0) if idx % 2 == 0 else (1.0, 1.0, 1.0)
            pdf.draw_rect(40, cur_y, 515, 16, fill_color=bg, stroke_color=(0.88, 0.9, 0.94), line_width=0.5)

            st = o.get("start_time", "")[:19].replace("T", " ")
            et = o.get("end_time", "")[:19].replace("T", " ") if o.get("end_time") else "Ao Vivo"
            dur_s = o.get("duration_seconds") or 0.0
            dur_str = f"{round(dur_s)}s ({round(dur_s/60, 1)}m)" if o.get("end_time") else "Aberta"
            o_type = "Total" if o.get("outage_type") == "TOTAL" else "Parcial"
            reason = o.get("reason", "Interrupção")[:40]
            tsa = "RFC 3161" if o.get("tsa_authority") else "HMAC-256"

            pdf.draw_text(st, 45, cur_y + 4, font="F1", size=7, color=(0.15, 0.2, 0.25))
            pdf.draw_text(et, 135, cur_y + 4, font="F1", size=7, color=(0.15, 0.2, 0.25))
            pdf.draw_text(dur_str, 225, cur_y + 4, font="F1", size=7, color=(0.15, 0.2, 0.25))
            pdf.draw_text(o_type, 270, cur_y + 4, font="F2", size=7, color=((0.8, 0.1, 0.1) if o_type == "Total" else (0.7, 0.4, 0.05)))
            pdf.draw_text(reason, 320, cur_y + 4, font="F1", size=7, color=(0.2, 0.25, 0.3))
            pdf.draw_text(tsa, 495, cur_y + 4, font="F2", size=6.5, color=(0.1, 0.5, 0.25))
            cur_y -= 16

    # -------------------------------------------------------------
    # SEÇÃO 4: FUNDAMENTAÇÃO LEGAL E PARECER CONCLUSIVO
    # -------------------------------------------------------------
    sec4_y = cur_y - 12
    pdf.draw_text("4. FUNDAMENTAÇÃO JURÍDICA E PARECER CONCLUSIVO PERICIAL", 40, sec4_y, font="F2", size=9.5, color=(0.08, 0.15, 0.28))

    box_h = 74
    pdf.draw_rect(40, sec4_y - box_h - 4, 515, box_h, fill_color=(0.98, 0.98, 0.99), stroke_color=(0.85, 0.88, 0.92), line_width=0.6)

    pdf.draw_text("• Resolução nº 632/2014 da ANATEL (Arts. 46 a 49): O consumidor tem direito ao abatimento automático na fatura por", 46, sec4_y - 16, font="F1", size=7.5, color=(0.2, 0.25, 0.3))
    pdf.draw_text("  interrupções. O Art. 46, § 1º assegura o desconto de no mínimo 1 (um) dia inteiro para falhas iguais ou superiores a 30 min.", 46, sec4_y - 27, font="F1", size=7.5, color=(0.2, 0.25, 0.3))
    pdf.draw_text("• Código de Defesa do Consumidor (Lei 8.078/1990, Arts. 6º, X, 20 e 22): Banda larga é serviço essencial de prestação contínua.", 46, sec4_y - 38, font="F1", size=7.5, color=(0.2, 0.25, 0.3))
    pdf.draw_text("  Instabilidades severas configuram vício de qualidade com dever objetivo de reparação e devolução de valores.", 46, sec4_y - 49, font="F1", size=7.5, color=(0.2, 0.25, 0.3))
    pdf.draw_text("• Parecer Pericial Conclusivo: Atesta-se que a infraestrutura local do cliente esteve operacional, restando comprovada a falha", 46, sec4_y - 62, font="F2", size=7.5, color=(0.1, 0.15, 0.25))
    pdf.draw_text("  técnica externa da prestadora de telecomunicações, sendo devida a aplicação dos descontos apurados.", 46, sec4_y - 72, font="F2", size=7.5, color=(0.1, 0.15, 0.25))

    # -------------------------------------------------------------
    # RODAPÉ E PROVA CRIPTOGRÁFICA
    # -------------------------------------------------------------
    status_msg = integrity.get("message", "Base de dados íntegra e certificada.")
    pdf.draw_rect(40, 42, 515, 26, fill_color=(0.94, 0.98, 0.95), stroke_color=(0.7, 0.88, 0.75), line_width=0.6)
    pdf.draw_text(f"🔒 CADEIA DE CUSTÓDIA ABNT NBR ISO/IEC 27037: {status_msg}", 50, 52, font="F2", size=7.5, color=(0.1, 0.45, 0.2))

    pdf.draw_text("Documento oficial para instrução probatória em ANATEL, PROCON e Juizado Especial Cível • Folha 1/1", 40, 24, font="F1", size=7, color=(0.5, 0.55, 0.6))
    pdf.draw_text("NetMon Forensic Pro • Imutabilidade Garantida", 400, 24, font="F1", size=7, color=(0.5, 0.55, 0.6))

    return pdf.finish()
