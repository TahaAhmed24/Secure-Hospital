from django.urls import path
from . import api_views as views

MedicalRecordViews = views.MedicalRecordViews
E2ESetupViews = views.E2ESetupViews
app_name = "records"

urlpatterns = [
    path('upload/', views.upload_page, name='upload_page'),
    path('api/e2ee/status/', E2ESetupViews.check_e2ee_status, name='check_e2ee_status'),
    path('api/keys/setup/', E2ESetupViews.setup_keys, name='setup_keys'),
    path('api/keys/me/', E2ESetupViews.get_user_keys, name='get_user_keys'),
    path('api/keys/user/<int:user_id>/', E2ESetupViews.get_public_key, name='get_public_key'),
    path('api/device/setup/', E2ESetupViews.setup_device, name='setup_device'),
    path('api/device/keys/', E2ESetupViews.get_device_keys, name='get_device_keys'),
    path('api/device/list/', E2ESetupViews.list_devices, name='list_devices'),
    path('api/device/revoke/', E2ESetupViews.revoke_device, name='revoke_device'),
    path('api/files/upload/', MedicalRecordViews.upload_file, name='upload_file'),
    path('api/files/list/', MedicalRecordViews.list_files, name='list_files'),
    path('api/files/<int:file_id>', MedicalRecordViews.get_file, name='get_file'),
    path('api/files/<int:file_id>/verify/', MedicalRecordViews.verify_signature_chain, name='verify_signature_chain'),
    path('api/files/new-version/', MedicalRecordViews.create_new_version, name='create_new_version'),
    path('api/files/<int:file_id>/download/', MedicalRecordViews.download_file, name='download_file'),
    path('api/files/<int:file_id>/metadata/', MedicalRecordViews.file_metadata, name='file_metadata'),
    path('api/files/<int:file_id>/share/', MedicalRecordViews.share_file, name='share_file'),
    path('api/files/<int:file_id>/versions/<int:version_id>/share/', MedicalRecordViews.share_access_to_version, name='share_access_to_version'),
    path('api/files/<int:file_id>/share-all-versions/', MedicalRecordViews.share_access_to_all_versions, name='share_access_to_all_versions'),
    path('api/files/<int:file_id>/approve/', MedicalRecordViews.approve_file, name='approve_file'),
    path('api/files/revoke-access/<int:user_id>', MedicalRecordViews.revoke_access_to_records, name='revoke_access'),
    path('api/files/<int:file_id>/reject/', MedicalRecordViews.reject_file, name='reject_file'),
    path('api/files/<int:file_id>/delete/', MedicalRecordViews.delete_file, name='delete_file'),
    path('api/files/<int:file_id>/request-deletion/', MedicalRecordViews.request_deletion, name='request_deletion'),
    path('api/files/<int:file_id>/approve-deletion/', MedicalRecordViews.approve_deletion, name='approve_deletion'),
    path('api/files/<int:file_id>/reject-deletion/', MedicalRecordViews.reject_deletion, name='reject_deletion'),
    path('api/files/<int:file_id>/access/', MedicalRecordViews.file_access_list, name='file_access_list'),
    path('api/files/<int:file_id>/versions/', MedicalRecordViews.list_file_versions, name='list_file_versions'),
    path('api/users/', views.list_users, name='list_users'),
]