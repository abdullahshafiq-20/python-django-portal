from flask import Blueprint, render_template, request, flash, redirect, url_for, send_file, abort, current_app
from flask_login import login_required, current_user
from flask_wtf.csrf import CSRFProtect

from project.utils import file_signature_valid
from . import db, env
from .models import Image, User, Evaluation
from .config import ALLOWED_FILETYPES
from .utils import is_bot
from .crypto import cipher
import base64
from datetime import datetime
import io
import os
from werkzeug.utils import secure_filename

main = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = ALLOWED_FILETYPES  # Define allowed file types

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route("/")
def index():
    return render_template("index.html")


@main.route("/profile")
@login_required
def profile():
    # Get user's evaluations if not admin
    evaluations = None
    if not current_user.is_admin:
        evaluations = Evaluation.query.filter_by(user_id=current_user.id)\
            .order_by(Evaluation.created_at.desc())\
            .all()
    
    return render_template(
        "profile.html",
        name=current_user.username,
        evaluations=evaluations
    )

@main.route("/password-policy")
def password_policy():
    return render_template("password_policy.html")



@main.route("/request-evaluation")
@login_required
def request_evaluation():
    if current_user.is_admin:
        return redirect(url_for('auth.admin_dashboard'))
    
    # Get user's previous evaluations
    previous_evaluations = Evaluation.query.filter_by(user_id=current_user.id).order_by(Evaluation.created_at.desc()).all()
    
    return render_template(
        "request_evaluation.html", 
        previous_evaluations=previous_evaluations,
        captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY']
    )

@main.route("/request-evaluation", methods=["POST"])
@login_required
def submit_evaluation():
    if is_bot(request):
        flash("Invalid Captcha")
        return redirect(url_for('main.request_evaluation'))

    item_description = request.form.get("item_description")
    contact_preference = request.form.get("contact_preference")
    contact_time = request.form.get("contact_time") if contact_preference == "phone" else None
    
    # Handle multiple photo uploads
    photos = request.files.getlist("item_photos")
    photo_ids = []
    
    for photo in photos:
        if photo:
            extension = photo.filename.split('.')[-1]
            
            if extension not in ALLOWED_FILETYPES:
                flash(f"{extension} files are not allowed!")
                return redirect(url_for("main.request_evaluation"))

            image_data = photo.read()
            if not file_signature_valid(extension, image_data):
                flash("Sorry, that file is invalid")
                return redirect(url_for("main.request_evaluation"))

            new_image = Image(
                posted_by=current_user.id,
                filetype=extension,
                image=cipher.encrypt(image_data),
                comments="Evaluation request photo"
            )
            db.session.add(new_image)
            db.session.flush()
            photo_ids.append(str(new_image.id))
    
    new_evaluation = Evaluation(
        user_id=current_user.id,
        item_description=item_description,
        item_photos=",".join(photo_ids),
        contact_preference=contact_preference,
        contact_time=contact_time,
        status="pending"
    )
    
    db.session.add(new_evaluation)
    db.session.commit()
    
    flash("Your evaluation request has been submitted successfully!")
    return redirect(url_for("main.request_evaluation"))

@main.route("/view-evaluation/<int:eval_id>")
@login_required
def view_evaluation(eval_id):
    evaluation = Evaluation.query.get_or_404(eval_id)
    
    # Only allow admin or the evaluation owner to view
    if not (current_user.is_admin or evaluation.user_id == current_user.id):
        flash("You don't have permission to view this evaluation")
        return redirect(url_for('main.profile'))
    
    # Get the photos
    photo_ids = evaluation.item_photos.split(",") if evaluation.item_photos else []
    photos = Image.query.filter(Image.id.in_(photo_ids)).all() if photo_ids else []
        
    return render_template(
        "view_evaluation.html",
        evaluation=evaluation,
        photos=photos
    )


@main.route("/evaluations")
@login_required
def evaluations():
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('main.profile'))
    
    evaluations = Evaluation.query.all()
    return render_template("evaluations.html", evaluations=evaluations)

@main.route("/image/<int:image_id>")
@login_required
def get_image(image_id):
    image = Image.query.get_or_404(image_id)
    
    # Check if user has permission to view this image
    if image.posted_by != current_user.id and not current_user.is_admin:
        abort(403)
    
    # Decrypt the image before sending
    try:
        decrypted_image = cipher.decrypt(image.image)
        return send_file(
            io.BytesIO(decrypted_image),
            mimetype=f'image/{image.filetype}',
            as_attachment=False
        )
    except Exception as e:
        logger.error(f"Failed to decrypt image: {str(e)}")
        abort(500)

@main.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Additional validation here

@main.route('/api/endpoint', methods=['POST'])
def api_endpoint():
    csrf = current_app.extensions['csrf']
    csrf.exempt(api_endpoint)
    # This route will not require CSRF token
    pass
