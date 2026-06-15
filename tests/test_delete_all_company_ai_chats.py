from report_harness import CompanyAIProvider

from scripts.delete_all_company_ai_chats import extract_chat_ids, _load_ids_file


def test_normalize_chat_list_path_strips_query_and_base_url():
    assert CompanyAIProvider._normalize_chat_list_path(
        'https://smartoa.china-entercom.com/smartbot/openapi/im/common/getSkillAllChatList'
        '?ownerAccount=s2487&pageNum=1&pageSize=50&fromSource=normal_chat',
    ) == 'common/getSkillAllChatList'
    assert CompanyAIProvider._normalize_chat_list_path('common/getSkillAllChatList') == (
        'common/getSkillAllChatList'
    )


def test_extract_chat_ids_finds_nested_conversation_ids():
    payload = {
        'success': True,
        'data': {
            'records': [
                {'conversationId': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'},
                {'uid': '11111111-2222-3333-4444-555555555555'},
            ],
            'other': {'id': 'not-a-uuid'},
        },
    }

    assert extract_chat_ids(payload) == [
        'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        '11111111-2222-3333-4444-555555555555',
    ]


def test_load_ids_file_skips_comments_and_blanks(tmp_path):
    path = tmp_path / 'chats.txt'
    path.write_text(
        '# comment\n\nabcdef01-2345-6789-abcd-ef0123456789\n',
        encoding='utf-8',
    )
    assert _load_ids_file(path) == ['abcdef01-2345-6789-abcd-ef0123456789']
